#!/bin/bash

#############################################################
# Server Setup Script for Debian-based Systems
#
# This script helps set up a new server with:
# - New user with sudo access
# - System hardening
# - Secure SSH configuration
# - Nginx Proxy Manager (primary reverse proxy on ports 80/443)
# - Docker and Docker Compose
#
#############################################################

# Script version - update this in one place for consistency
readonly SCRIPT_VERSION="0.9-101425-2001"

# Text colors and banner formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Consistent banner function
banner_print() {
    echo -e "${PURPLE}# ╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}# ║                                                              ║${NC}"
    echo -e "${PURPLE}# ║                          ____                                ║${NC}"
    echo -e "${PURPLE}# ║      _ __   _____      _/ ___|  ___ _ ____   _____ _ __      ║${NC}"
    echo -e "${PURPLE}# ║     | '_ \ / _ \ \ /\ / |___ \ / _ \ '__\ \ / / _ \ '__|     ║${NC}"
    echo -e "${PURPLE}# ║     | | | |  __/\ V  V / ___) |  __/ |   \ V /  __/ |        ║${NC}"
    echo -e "${PURPLE}# ║     |_| |_|\___| \_/\_/ |____/ \___|_|    \_/ \___|_|        ║${NC}"
    echo -e "${PURPLE}# ║                                                              ║${NC}"
    echo -e "${PURPLE}# ╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${CYAN}       Script: ${0}$ | Version: ${SCRIPT_VERSION}${NC}"
    echo -e ""
}

# Logging setup
LOGFILE="/var/log/server_setup.log"
mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
touch "$LOGFILE" 2>/dev/null

# Functions
log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} - $1" >> "$LOGFILE"
}

log_section() {
    echo -e "\n${PURPLE}===========================${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}===========================${NC}\n"
    log "SECTION: $1"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
    log "SUCCESS: $1"
}

info() {
    echo -e "${BLUE}ℹ $1${NC}"
    log "INFO: $1"
}

warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
    log "WARNING: $1"
}

error() {
    echo -e "${RED}✗ $1${NC}" >&2
    log "ERROR: $1"
}

instruction() {
    echo -e "${CYAN}>> $1${NC}"
    log "INSTRUCTION: $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root or with sudo privileges."
        exit 1
    fi
    success "Running with root privileges."
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" == *"debian"* ]]; then
            success "Detected supported OS: $PRETTY_NAME"
            return 0
        fi
    fi
    error "This script is designed for Debian-based systems (e.g., Ubuntu, Debian)."
    exit 1
}

random_port() {
    # Generate a random port number between 10000 and 65535
    echo $((RANDOM % 55535 + 10000))
}

# Standardized input functions for consistent UX
prompt_options() {
    local title="$1"
    local prompt="$2"
    local var_name="$3"
    local options=("${@:4}")

    # Check if terminal supports ANSI colors
    if [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
        # Use ANSI colors
        echo -e "${BLUE}┌─ ${title}${NC}"
        echo -e "${BLUE}│${NC}"
        for i in "${!options[@]}"; do
            echo -e "${BLUE}│  $((i+1)): ${options[$i]}${NC}"
        done
        echo -e "${BLUE}│${NC}"
        echo -n "${BLUE}${prompt} ${NC}"
    else
        # Plain text fallback
        echo "┌─ $title"
        echo "│"
        for i in "${!options[@]}"; do
            echo "│  $((i+1)): ${options[$i]}"
        done
        echo "│"
        echo -n "$prompt "
    fi

    local choice
    read -r choice

    # Validate input
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
        eval "$var_name=$choice"
        return 0
    else
        # Handle error message with color detection
        if [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
            echo -e "${YELLOW}Invalid option. Please select 1-${#options[@]}${NC}"
        else
            echo "Invalid option. Please select 1-${#options[@]}"
        fi
        prompt_options "$title" "$prompt" "$var_name" "${options[@]}"
        return $?
    fi
}

generate_password() {
    # Generate a strong random password (16 characters)
    < /dev/urandom tr -dc 'A-Za-z0-9!#$%&()*+,-./:;<=>?@[\]^_{|}~' | head -c 16
}

cleanup() {
    log "Script execution interrupted. Cleaning up..."
    # Add cleanup tasks if needed
    exit 1
}

# Trap for cleanup on script termination
trap cleanup SIGINT SIGTERM

#############################################################
# Main Script Execution
#############################################################

clear
banner_print

log_section "Starting Server Setup"
check_root
check_os

instruction "Let's collect all the configuration information first."
instruction "After reviewing your choices, you'll be asked to confirm before any changes are made."

#############################################################
# Configuration Collection Phase
#############################################################
log_section "Configuration Collection"

# User Management Configuration
prompt_options "User & Access Configuration" "Select option:" USER_CONFIG_CHOICE \
    "Create New Admin User - Secure account with sudo privileges" \
    "Use Existing User - Configure existing user account" \
    "Skip User Setup - Manual user setup required"

# User creation handling
USER_EXISTS=false
CREATE_NEW_USER=false

if [[ "$USER_CONFIG_CHOICE" == "1" ]]; then
    # Create new user
    CREATE_NEW_USER=true
    read -p "Enter username for the new user (leave blank for 'admin'): " NEW_USER
    NEW_USER=${NEW_USER:-admin}

    # Check if user already exists
    if id "$NEW_USER" &>/dev/null; then
        warn "User '$NEW_USER' already exists."
        read -p "Do you want to proceed with the existing user? [y/n]: " proceed
        if [[ "$proceed" != "y" && "$proceed" != "Y" ]]; then
            error "Setup cancelled by user."
            exit 1
        fi
        USER_EXISTS=true
        CREATE_NEW_USER=false
        info "Will configure existing user '$NEW_USER'."
    fi

elif [[ "$USER_CONFIG_CHOICE" == "2" ]]; then
    # Configure existing user
    USER_EXISTS=true
    read -p "Enter the username of the existing user to configure: " NEW_USER
    if ! id "$NEW_USER" &>/dev/null; then
        error "User '$NEW_USER' does not exist."
        exit 1
    fi
    info "Will configure existing user '$NEW_USER'."
fi

# Password configuration (only for new users)
if [[ "$CREATE_NEW_USER" == "true" ]]; then
    prompt_options "Password Configuration" "Select option:" PASSWORD_CHOICE \
        "Generate Secure Password - Automatic strong password creation" \
        "Enter Custom Password - Manual password entry and confirmation"

    if [[ "$PASSWORD_CHOICE" == "1" ]]; then
        USER_PASS=$(generate_password)
        GEN_PASS="y"
    else
        read -s -p "Enter password for the new user: " USER_PASS
        echo
        read -s -p "Confirm password: " USER_PASS_CONFIRM
        echo
        if [[ "$USER_PASS" != "$USER_PASS_CONFIRM" ]]; then
            error "Passwords do not match."
            exit 1
        fi
        GEN_PASS="n"
    fi
fi

# System Configuration
prompt_options "SSH Port Configuration" "Select option:" SSH_PORT_CHOICE \
    "Use Default SSH Port (22) - Standard port for compatibility" \
    "Use Random SSH Port - Enhanced security with automatic selection" \
    "Choose Custom SSH Port - Full control (enter manually)" \
    "Skip SSH Port Config - Keep current settings"

SSH_PORT=""
DEFAULT_SSH_PORT=$(random_port)

case $SSH_PORT_CHOICE in
    1)
        SSH_PORT=22
        info "Will use default SSH port: 22"
        ;;
    2)
        SSH_PORT=$DEFAULT_SSH_PORT
        info "Will use randomly generated SSH port: $SSH_PORT"
        ;;
    3)
        read -p "Enter your preferred SSH port: " SSH_PORT
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
            warn "Port $SSH_PORT is invalid. Using default port 22."
            SSH_PORT=22
        fi
        ;;
    4)
        SSH_PORT=22  # Default fallback
        ;;
esac

# Hostname configuration
CURRENT_HOSTNAME=$(hostname)
read -p "Enter hostname for the server (leave blank for '$CURRENT_HOSTNAME'): " SERVER_HOSTNAME
SERVER_HOSTNAME=${SERVER_HOSTNAME:-$CURRENT_HOSTNAME}

# Server access URL/IP
read -p "Enter the IP address or domain you'll use to access this server: " SERVER_ACCESS_URL
SERVER_ACCESS_URL=${SERVER_ACCESS_URL:-$(hostname -I | awk '{print $1}')}

# Service Configuration
prompt_options "Additional Services Configuration" "Select option:" SERVICES_CHOICE \
    "Enable All Services - GitHub access, monitoring, and automatic updates" \
    "Selective Services - Choose which services to enable" \
    "Minimal Services Only - Skip optional services" \
    "No Additional Services - Manual configuration required"

SETUP_GITHUB="n"
SETUP_LOGWATCH="n"
ENABLE_AUTO_UPDATES="n"

case $SERVICES_CHOICE in
    1)
        SETUP_GITHUB="y"
        SETUP_LOGWATCH="y"
        ENABLE_AUTO_UPDATES="y"
        info "All services will be configured."
        ;;
    2)
        # GitHub configuration
        prompt_options "GitHub SSH Access" "Select option:" GITHUB_CHOICE \
            "Enable GitHub SSH Access - Automated key generation and setup" \
            "Skip GitHub Setup - Manual configuration required"

        if [[ "$GITHUB_CHOICE" == "1" ]]; then
            SETUP_GITHUB="y"
            read -p "Enter your GitHub username: " GIT_USER
            read -p "Enter your Git commit email address: " GIT_EMAIL
        fi

        # Logwatch configuration
        prompt_options "System Monitoring" "Select option:" LOGWATCH_CHOICE \
            "Enable Daily Log Analysis - Automated system monitoring" \
            "Skip Log Monitoring - Manual log management"

        if [[ "$LOGWATCH_CHOICE" == "1" ]]; then
            SETUP_LOGWATCH="y"
        fi

        # Automatic updates configuration
        prompt_options "Automatic Security Updates" "Select option:" UPDATES_CHOICE \
            "Enable Auto Security Updates - Weekly system security updates" \
            "Skip Auto Updates - Manual update management"

        if [[ "$UPDATES_CHOICE" == "1" ]]; then
            ENABLE_AUTO_UPDATES="y"
            # Default to weekly - could add another prompt for frequency
            AUTO_UPDATE_FREQUENCY="weekly"
        fi
        ;;
    3|4)
        # Already set to "n" above
        info "Optional services will be skipped."
        ;;
esac

# Set frequency for auto updates if enabled
if [[ "$ENABLE_AUTO_UPDATES" == "y" ]]; then
    prompt_options "Update Frequency" "Select frequency:" UPDATE_FREQ_CHOICE \
        "Weekly Updates - Regular security maintenance" \
        "Monthly Updates - Less frequent update checks"

    case $UPDATE_FREQ_CHOICE in
        1) AUTO_UPDATE_FREQUENCY="weekly" ;;
        2) AUTO_UPDATE_FREQUENCY="monthly" ;;
    esac
fi

GIT_USER=""
GIT_EMAIL=""
if [[ "$SETUP_GITHUB" == "y" ]]; then
    read -p "Enter your GitHub username: " GIT_USER
    read -p "Enter your Git commit email address: " GIT_EMAIL
fi

#############################################################
# Configuration Summary and Confirmation
#############################################################
log_section "Configuration Review"

echo -e "${CYAN}Please review your configuration choices:${NC}"
echo -e "${BLUE}├─ User Management:${NC}"
if [[ "$USER_EXISTS" == "true" ]]; then
    echo -e "${BLUE}│  ├─ User:${NC} $NEW_USER (existing user)"
else
    echo -e "${BLUE}│  ├─ User:${NC} $NEW_USER (will be created)"
    if [[ "${GEN_PASS:-n}" == "n" || "${GEN_PASS:-n}" == "N" ]]; then
        echo -e "${BLUE}│  └─ Password:${NC} Provided by user"
    else
        echo -e "${BLUE}│  └─ Password:${NC} Will be automatically generated and shown once"
    fi
fi

echo -e "${BLUE}├─ System Configuration:${NC}"
echo -e "${BLUE}├─ Hostname:${NC} $CURRENT_HOSTNAME → $SERVER_HOSTNAME"
echo -e "${BLUE}├─ SSH Port:${NC} 22 → $SSH_PORT"
echo -e "${BLUE}├─ Server Access URL:${NC} $SERVER_ACCESS_URL"

echo -e "${BLUE}├─ GitHub Configuration:${NC}"
if [[ "$SETUP_GITHUB" != "n" && "$SETUP_GITHUB" != "N" ]]; then
    echo -e "${BLUE}├─ Username:${NC} $GIT_USER"
    echo -e "${BLUE}└─ Email:${NC} $GIT_EMAIL"
else
    echo -e "${BLUE}└─ GitHub Setup: NO${NC}"
fi

echo -e "${BLUE}├─ Services to Install:${NC}"
echo -e "${BLUE}│  ├─ Docker & Docker Compose${NC}"
echo -e "${BLUE}│  ├─ Nginx Proxy Manager (ports 80,443,81)${NC}"
echo -e "${BLUE}│  ├─ Git & SSH configuration${NC}"
if [[ "$SETUP_GITHUB" != "n" && "$SETUP_GITHUB" != "N" ]]; then
    echo -e "${BLUE}│  └─ GitHub SSH setup${NC}"
else
    echo -e "${BLUE}│  └─ GitHub SSH setup: NO${NC}"
fi
if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then
    echo -e "${BLUE}└─ Logwatch (daily log analysis)${NC}"
else
    echo -e "${BLUE}└─ Logwatch: NO${NC}"
fi

echo -e "${BLUE}├─ Automatic Updates:${NC}"
if [[ "$ENABLE_AUTO_UPDATES" != "n" && "$ENABLE_AUTO_UPDATES" != "N" ]]; then
    echo -e "${BLUE}└─ Security updates enabled (${AUTO_UPDATE_FREQUENCY})${NC}"
else
    echo -e "${BLUE}└─ Automatic updates: NO${NC}"
fi

echo
prompt_options "Final Confirmation" "Select option:" CONFIRMATION \
    "Yes - Proceed with this server setup configuration" \
    "No - Cancel setup and make no changes"

if [[ "$CONFIRMATION" == "2" ]]; then
    info "Setup cancelled by user."
    exit 0
fi

success "Configuration confirmed. Proceeding with setup..."

#############################################################
# User Management Execution
#############################################################
log_section "Creating User"

if [[ "$CREATE_NEW_USER" == "true" ]]; then
    # Create user
    info "Creating new user '$NEW_USER'..."
    useradd -m -s /bin/bash "$NEW_USER" || { error "Failed to create user."; exit 1; }
    echo "$NEW_USER:$USER_PASS" | chpasswd || { error "Failed to set password."; exit 1; }

    # Add user to sudo group
    usermod -aG sudo "$NEW_USER" || { error "Failed to add user to sudo group."; exit 1; }
    success "User '$NEW_USER' created and added to the sudo group."

    if [[ "$GEN_PASS" != "n" && "$GEN_PASS" != "N" ]]; then
        warn "AUTO-GENERATED PASSWORD: $USER_PASS"
        instruction "⚠️  SAVE THIS PASSWORD IMMEDIATELY! It will not be shown again."
    fi
fi

# Set hostname
if [[ "$SERVER_HOSTNAME" != "$CURRENT_HOSTNAME" ]]; then
    hostnamectl set-hostname "$SERVER_HOSTNAME"
    success "Server hostname changed from '$CURRENT_HOSTNAME' to '$SERVER_HOSTNAME'"
else
    success "Keeping current hostname: $CURRENT_HOSTNAME"
fi


# Update and upgrade system
log_section "Updating System Packages"
info "Updating package lists. This might take a few minutes..."
apt-get update -qq || { error "Failed to update package lists."; exit 1; }
success "Package lists updated."

info "Upgrading installed packages. This might take a while..."
apt-get upgrade -y -qq || { error "Failed to upgrade packages."; exit 1; }
success "Packages upgraded."

# Install required packages
log_section "Installing Required Packages"
info "Installing essential packages..."
apt-get install -y -qq \
    sudo \
    ufw \
    fail2ban \
    curl \
    gnupg2 \
    ca-certificates \
    lsb-release \
    apt-transport-https \
    unattended-upgrades \
    git \
    htop \
    iotop \
    ncdu \
    net-tools || { error "Failed to install essential packages."; exit 1; }
success "Essential packages installed."

# Install Docker
log_section "Installing Docker"
info "Installing Docker and Docker Compose..."

# Add Docker's official GPG key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository to Apt sources
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
   tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package list and install Docker
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || { error "Failed to install Docker."; exit 1; }

# Determine compose command to use
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    # Fallback to standalone docker-compose (install if needed)
    if ! command -v docker-compose &> /dev/null; then
        apt-get install -y -qq docker-compose || { error "Failed to install docker-compose."; exit 1; }
    fi
    COMPOSE_CMD="docker-compose"
fi
info "Using Docker Compose command: $COMPOSE_CMD"

# Start and enable Docker service
systemctl enable docker
systemctl start docker

# Add the new user to the docker group
usermod -aG docker "$NEW_USER" || { error "Failed to add user to docker group."; exit 1; }

success "Docker installed and configured successfully."
success "User '$NEW_USER' added to docker group."

#############################################################
# System Hardening
#############################################################
log_section "System Hardening"

# Configure unattended upgrades
info "Configuring unattended security updates..."
if [[ "$ENABLE_AUTO_UPDATES" != "n" && "$ENABLE_AUTO_UPDATES" != "N" ]]; then

    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    # Create cron job for automatic security updates based on selected frequency
    if [[ "$AUTO_UPDATE_FREQUENCY" == "weekly" ]]; then
        cat > /etc/cron.d/security-updates-weekly << EOF
# Weekly security updates - $(date)
@weekly root /usr/bin/unattended-upgrade -v --dry-run | /usr/bin/logger -t unattended-upgrade
@weekly root /usr/bin/unattended-upgrade -v
EOF
        success "Security updates configured for weekly execution."
    elif [[ "$AUTO_UPDATE_FREQUENCY" == "monthly" ]]; then
        cat > /etc/cron.d/security-updates-monthly << EOF
# Monthly security updates - $(date)
@monthly root /usr/bin/unattended-upgrade -v --dry-run | /usr/bin/logger -t unattended-upgrade
@monthly root /usr/bin/unattended-upgrade -v
EOF
        success "Security updates configured for monthly execution."
    fi

    # Create MOTD update script to show pending updates
    cat > /etc/cron.daily/update-motd-updates << EOF
#!/bin/bash
# Update MOTD with available updates count

UPDATES=\$(apt-get -s upgrade 2>/dev/null | grep -P "^\d+ upgraded" | cut -d" " -f1)

if [ "\$UPDATES" -gt 0 ]; then
    cat > /etc/motd << EOM

Welcome to $SERVER_HOSTNAME

SYSTEM STATUS:
- You have \$UPDATES pending package updates available
- Run 'sudo apt-get update && sudo apt-get upgrade' to apply them
- Last system update: \$(date)

EOM
fi
EOF

    chmod +x /etc/cron.daily/update-motd-updates
    success "MOTD update notification configured."

else
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "7";
EOF
    success "Automatic updates disabled (manual updates required)."
fi

# Configure Fail2Ban
info "Configuring Fail2Ban for SSH protection..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl restart fail2ban
success "Fail2Ban configured for SSH protection."

# Configure sysctl for security
info "Hardening network settings..."
cat > /etc/sysctl.d/99-security.conf << EOF
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 if not needed (comment out if IPv6 is required)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Increase system file descriptor limit
fs.file-max = 65535
EOF

sysctl -p /etc/sysctl.d/99-security.conf
success "Network settings hardened."

# Secure shared memory
info "Securing shared memory..."
if ! grep -q '/run/shm' /etc/fstab; then
    echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
    mount -o remount /run/shm
    success "Shared memory secured."
else
    success "Shared memory already secured."
fi

#############################################################
# Firewall Configuration
#############################################################
log_section "Firewall Configuration (UFW)"

# Configure UFW
info "Configuring firewall with UFW..."
info "Using previously selected SSH port: $SSH_PORT"

# Reset and disable UFW to start fresh
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH on the configured port
ufw allow "$SSH_PORT"/tcp comment 'SSH access'

# Allow HTTP and HTTPS for Nginx Proxy Manager
ufw allow 80/tcp comment 'HTTP for Nginx Proxy Manager'
ufw allow 443/tcp comment 'HTTPS for Nginx Proxy Manager'

# Enable UFW
info "Enabling UFW firewall..."
ufw --force enable
ufw status verbose | tee -a "$LOGFILE"
success "Firewall configured and enabled."

#############################################################
# SSH Configuration
#############################################################
log_section "SSH Configuration"

info "Configuring SSH..."

# Create SSH directory for the new user
mkdir -p /home/$NEW_USER/.ssh
chmod 700 /home/$NEW_USER/.ssh
chown $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh

# Provide SSH key setup instructions for Windows compatibility
instruction ""
instruction "=== SSH Key Authentication Setup ==="
instruction ""
instruction "To securely access your server, set up SSH key authentication."
instruction "Multiple methods are provided for different systems:"
instruction ""

instruction "METHOD 1: Windows OpenSSH (Windows 10+ recommended):"
instruction "1. Open Command Prompt or PowerShell as administrator"
instruction '2. Generate SSH keys: ssh-keygen -t rsa -b 4096 -C "your-email@example.com"'
instruction '3. Copy to server: cat ~/.ssh/id_rsa.pub | ssh Administrator@$SERVER_ACCESS_URL "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"'
instruction '4. Set permissions: ssh Administrator@$SERVER_ACCESS_URL "chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"'
instruction '5. Test: ssh -p $SSH_PORT Administrator@$SERVER_ACCESS_URL'
instruction ""

instruction "METHOD 2: Git Bash (Windows):"
instruction "1. Open Git Bash"
instruction '2. Generate keys: ssh-keygen -t rsa -b 4096 -C "your-email@example.com"'
instruction '3. Copy using SCP: scp -P $SSH_PORT ~/.ssh/id_rsa.pub Administrator@$SERVER_ACCESS_URL:~/.ssh/authorized_keys'
instruction '4. Set permissions: ssh -p $SSH_PORT Administrator@$SERVER_ACCESS_URL "chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"'
instruction ""

instruction "METHOD 3: PowerShell Native:"
instruction "1. Open PowerShell"
instruction '2. Install OpenSSH: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0'
instruction '3. Generate keys: ssh-keygen -t rsa -b 4096 -C "your-email@example.com"'
instruction '4. Copy keys: Get-Content ~/.ssh/id_rsa.pub | ssh -p $SSH_PORT Administrator@$SERVER_ACCESS_URL "cat >> ~/.ssh/authorized_keys"'
instruction ""

instruction "METHOD 4: PuTTY (Windows - Legacy):"
instruction "1. Generate keys with PuTTYgen"
instruction "2. Save private key as .ppk file"
instruction "3. Copy public key to server clipboard"
instruction '4. Add to server: ssh -p $SSH_PORT Administrator@$SERVER_ACCESS_URL "mkdir -p ~/.ssh && echo \'PASTE_PUBLIC_KEY_HERE\' >> ~/.ssh/authorized_keys"'
instruction ""

instruction "Universal Steps (after key copy):"
instruction '1. Set permissions: chmod 600 ~/.ssh/id_rsa (local)'
instruction '2. Test connection: ssh -p $SSH_PORT -i ~/.ssh/id_rsa Administrator@$SERVER_ACCESS_URL'
instruction '3. Disable password auth after testing: Consider setting "PasswordAuthentication no" in /etc/ssh/sshd_config'
instruction ""

instruction "SECURITY: Save your private keys securely and never share them!"
instruction "The server currently accepts both password and key authentication."
instruction ""
success "SSH directory created for '$NEW_USER'. Windows-compatible key setup methods provided above."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH
info "Configuring SSH (with optional key-based authentication)..."
cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration
Port $SSH_PORT
Protocol 2

# Authentication (Modified for flexibility)
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Restrict users
AllowUsers $NEW_USER

# Hardening
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
MaxAuthTries 5
LoginGraceTime 60
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Other
TCPKeepAlive yes
Compression delayed
EOF

info "Configuring SSH client to use the new port..."
mkdir -p /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/local.conf << EOF
Host *
    Port $SSH_PORT
EOF

# Test SSH configuration
info "Testing SSH configuration..."
sshd -t
if [ $? -eq 0 ]; then
    success "SSH configuration is valid."
    # We'll restart SSH service at the very end of the script
else
    error "SSH configuration test failed. Reverting to original configuration."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
fi



#############################################################
# Nginx Proxy Manager Installation
#############################################################
log_section "Nginx Proxy Manager Installation"

info "Installing Nginx Proxy Manager with Docker..."

# Create directories for Nginx Proxy Manager
mkdir -p /opt/npm/data
mkdir -p /opt/npm/letsencrypt

# Create Docker Compose file for Nginx Proxy Manager
cat > /opt/npm/docker-compose.yml << EOF
services:
  npm:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
    environment:
      DB_SQLITE_FILE: "/data/database.sqlite"
      DISABLE_IPV6: 'true'
    networks:
      - reverse_proxy

networks:
  reverse_proxy:
EOF

# Set proper permissions
chmod 600 /opt/npm/docker-compose.yml
if id "$NEW_USER" &>/dev/null; then
    chown -R "$NEW_USER:$NEW_USER" /opt/npm
else
    warn "User $NEW_USER not found, skipping ownership change for NPM directories."
fi

# Start Nginx Proxy Manager
info "Starting Nginx Proxy Manager..."
cd /opt/npm
$COMPOSE_CMD up -d || { error "Failed to start Nginx Proxy Manager."; exit 1; }

# Wait for NPM to initialize
info "Waiting for Nginx Proxy Manager to initialize..."
sleep 30

# Check if NPM is running
if $COMPOSE_CMD ps | grep -q "Up"; then
    success "Nginx Proxy Manager installed and started successfully."
    log "NGINX_PROXY_MANAGER: Web Interface accessible at http://your-server-ip:81"
    log "NGINX_PROXY_MANAGER: Default Admin Email: admin@example.com"
    log "NGINX_PROXY_MANAGER: Default Admin Password: changeme"
    log "SECURITY_WARNING: Nginx Proxy Manager default credentials must be changed immediately"
    info "Nginx Proxy Manager will be available at:"
    info "  Web Interface: http://your-server-ip:81"
    info "  Default Admin Email: admin@example.com"
    info "  Default Admin Password: changeme"
    instruction "IMPORTANT: Change the default password immediately after first login!"
else
    error "Nginx Proxy Manager failed to start properly."
    warn "You may need to start it manually with: cd /opt/npm && $COMPOSE_CMD up -d"
fi

#############################################################
# GitHub Access Setup
#############################################################
log_section "GitHub Access Setup"

info "Setting up Git for user '$NEW_USER'..."

# Configure Git for the new user - use provided credentials if GitHub setup chosen
if [[ "$SETUP_GITHUB" != "n" && "$SETUP_GITHUB" != "N" && -n "$GIT_USER" ]]; then
    su - "$NEW_USER" -c "git config --global user.name \"$GIT_USER\""
    su - "$NEW_USER" -c "git config --global user.email \"$GIT_EMAIL\""
else
    # Fallback if no GitHub setup or credentials
    su - "$NEW_USER" -c "git config --global user.name \"$NEW_USER\""
    su - "$NEW_USER" -c "git config --global user.email \"$NEW_USER@$SERVER_HOSTNAME\""
fi

# Generate SSH key for GitHub if user wants to
read -p "Set up SSH key for GitHub access? [Y/n]: " SETUP_GITHUB
if [[ "$SETUP_GITHUB" != "n" && "$SETUP_GITHUB" != "N" ]]; then
    # Generate GitHub SSH key
    info "Generating SSH key for GitHub..."
    
    # Create SSH config file to separate GitHub key
    mkdir -p "/home/$NEW_USER/.ssh"
    
    if [ ! -f "/home/$NEW_USER/.ssh/config" ]; then
        cat > "/home/$NEW_USER/.ssh/config" << EOF
Host github.com
    HostName github.com
    IdentityFile ~/.ssh/github_rsa
    User git
EOF
    else
        info "SSH config file already exists. Please manually add GitHub configuration if needed."
    fi
    
    # Generate the GitHub SSH key
    GIT_SSH_KEY="/home/$NEW_USER/.ssh/github_rsa"
    su - "$NEW_USER" -c "ssh-keygen -t rsa -b 4096 -f \"$GIT_SSH_KEY\" -N \"\" -C \"$NEW_USER@$SERVER_HOSTNAME-github\""
    
    # Display the GitHub public key
    echo
    info "GitHub SSH public key (add this to your GitHub account):"
    cat "$GIT_SSH_KEY.pub"
    echo
    
    instruction "Add the above key to your GitHub account:"
    instruction "1. Log into GitHub"
    instruction "2. Go to Settings > SSH and GPG keys"
    instruction "3. Click 'New SSH key'"
    instruction "4. Paste the key and give it a title"
    
    chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
    success "GitHub SSH key generated."
    
    info "Testing GitHub SSH connection (this may fail if you haven't added the key to GitHub yet)..."
    su - "$NEW_USER" -c "ssh -T -o StrictHostKeyChecking=no git@github.com" || true
    
    instruction "To clone a repository, use: git clone git@github.com:username/repo.git"
fi

#############################################################
# System Monitoring & Logging
#############################################################
log_section "System Monitoring & Logging"

info "Setting up log rotation..."
cat > /etc/logrotate.d/custom << EOF
/var/log/server_setup.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
success "Log rotation configured."

# Configure Logwatch if requested
if [[ "$SETUP_LOGWATCH" == "y" ]]; then
    info "Installing and configuring Logwatch..."
    apt-get install -y -qq logwatch

    # Configure Logwatch for daily reports
    mkdir -p /etc/logwatch/conf
    cat > /etc/logwatch/conf/logwatch.conf << EOF
LogDir = /var/log
TmpDir = /var/cache/logwatch
Output = mail
Format = html
Encode = none
MailTo = root
Range = yesterday
Detail = Medium
Service = All
EOF

    success "Logwatch installed and configured for daily reports."
fi

#############################################################
# Final Steps and Summary
#############################################################
log_section "Setup Complete"

# Create a summary file
SUMMARY_FILE="/home/$NEW_USER/server_setup_summary.txt"

          SERVER SETUP SUMMARY
cat > "$SUMMARY_FILE" << EOF
          SERVER SETUP SUMMARY

SYSTEM INFORMATION:
------------------
Date: $(date)
Hostname: $SERVER_HOSTNAME
IP Address: $(hostname -I | awk '{print $1}')

USER ACCESS:
------------------
Admin User: $NEW_USER
SSH Port: $SSH_PORT

SECURITY MEASURES:
------------------
✓ System updated and upgraded
✓ Firewall (UFW) enabled
✓ SSH hardened (key-based auth only)
✓ Fail2Ban configured
✓ Root login disabled
✓ Automatic security updates enabled
✓ Network settings hardened

INSTALLED SERVICES:
------------------
✓ Nginx Proxy Manager (main reverse proxy - listens on ports 80/443)
✓ Docker and Docker Compose (ready for container deployment)
✓ Git (configured for GitHub access)
$(if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then echo "✓ Logwatch (daily log analysis)"; fi)

FIREWALL RULES:
------------------
$(ufw status | grep -v "Status")

NEXT STEPS:
------------------
1. Save your SSH private keys to your local machine
2. Delete the private keys from the server
3. Test SSH login with: ssh -p $SSH_PORT $NEW_USER@your_server_ip
4. Configure SSL/TLS for Nginx (Let's Encrypt recommended)
5. Configure your applications with Nginx
6. Review and customize security settings as needed

For more details, check the log file at $LOGFILE
EOF
          SERVER SETUP SUMMARY
          SERVER SETUP SCRIPT v0.9-101425-2001
          SERVER SETUP SUMMARY

SYSTEM INFORMATION:
------------------
Date: $(date)
Hostname: $SERVER_HOSTNAME
IP Address: $(hostname -I | awk '{print $1}')

USER ACCESS:
------------------
Admin User: $NEW_USER
SSH Port: $SSH_PORT

SECURITY MEASURES:
------------------
✓ System updated and upgraded
✓ Firewall (UFW) enabled
✓ SSH hardened (key-based auth only)
✓ Fail2Ban configured
✓ Root login disabled
✓ Automatic security updates enabled
✓ Network settings hardened

INSTALLED SERVICES:
------------------
✓ Nginx Proxy Manager (main reverse proxy - listens on ports 80/443)
✓ Docker and Docker Compose (ready for container deployment)
✓ Git (configured for GitHub access)
$(if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then echo "✓ Logwatch (daily log analysis)"; fi)

FIREWALL RULES:
------------------
$(ufw status | grep -v "Status")

ADDITIONAL CONFIGURATION:
------------------------
$(if [[ "$ENABLE_AUTO_UPDATES" != "n" && "$ENABLE_AUTO_UPDATES" != "N" ]]; then echo "✓ Automatic security updates enabled (${AUTO_UPDATE_FREQUENCY})"; else echo "✗ Automatic updates disabled"; fi)
$(if [[ "$RUN_CLEANUP" != "n" && "$RUN_CLEANUP" != "N" ]]; then echo "✓ System optimization completed"; else echo "✗ System cleanup was skipped"; fi)

NEXT STEPS:
------------------
1. Save your SSH private keys to your local machine
2. Delete the private keys from the server
3. Test SSH login with: ssh -p $SSH_PORT $NEW_USER@your_server_ip
4. Configure SSL/TLS for Nginx (Let's Encrypt recommended)
5. Configure your applications with Nginx
6. Review and customize security settings as needed

For more details, check the log file at $LOGFILE
EOF
========================================================
          SERVER SETUP SUMMARY
========================================================

SYSTEM INFORMATION:
------------------
Date: $(date)
Hostname: $SERVER_HOSTNAME
IP Address: $(hostname -I | awk '{print $1}')

USER ACCESS:
------------------
Admin User: $NEW_USER
SSH Port: $SSH_PORT

SECURITY MEASURES:
------------------
✓ System updated and upgraded
✓ Firewall (UFW) enabled
✓ SSH hardened (key-based auth only)
✓ Fail2Ban configured
✓ Root login disabled
✓ Automatic security updates enabled
✓ Network settings hardened

INSTALLED SERVICES:
------------------
✓ Nginx Proxy Manager (main reverse proxy - listens on ports 80/443)
✓ Docker and Docker Compose (ready for container deployment)
✓ Git (configured for GitHub access)
$(if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then echo "✓ Logwatch (daily log analysis)"; fi)

FIREWALL RULES:
------------------
$(ufw status | grep -v "Status")

NEXT STEPS:
------------------
1. Save your SSH private keys to your local machine
2. Delete the private keys from the server
3. Test SSH login with: ssh -p $SSH_PORT $NEW_USER@your_server_ip
4. Configure SSL/TLS for Nginx (Let's Encrypt recommended)
5. Configure your applications with Nginx
6. Review and customize security settings as needed

For more details, check the log file at $LOGFILE
========================================================
EOF

chown "$NEW_USER:$NEW_USER" "$SUMMARY_FILE"
chmod 600 "$SUMMARY_FILE"

# Display summary
info "Setup completed successfully! A summary has been saved to: $SUMMARY_FILE"
instruction "Next steps:"
instruction "1. Save your SSH private keys to your local machine"
instruction "2. Delete the private keys from the server after saving them"
instruction "3. Log out and test SSH login with: ssh -i /path/to/key -p $SSH_PORT $NEW_USER@SERVER_IP"
instruction "4. If everything works, consider removing password authentication completely"

info "To view the setup summary: cat $SUMMARY_FILE"

# System cleanup and optimization
log_section "System Cleanup & Optimization"

read -p "Run system optimization (remove orphaned packages and clean cache)? [Y/n]: " RUN_CLEANUP

if [[ "$RUN_CLEANUP" != "n" && "$RUN_CLEANUP" != "N" ]]; then
    info "Performing system cleanup and optimization..."
    
    # Show what will be removed (dry run first)
    info "Analyzing orphaned packages..."
    ORPHANED_PACKAGES=$(apt-get autoremove --dry-run 2>/dev/null | grep "^ " | tr -d ' ' | grep -v "^$" | wc -l)
    
    if [ "$ORPHANED_PACKAGES" -gt 0 ]; then
        warn "Found $ORPHANED_PACKAGES orphaned packages that can be safely removed."
        apt-get autoremove --dry-run 2>/dev/null | grep "^ " || true
        echo
        read -p "Proceed with removing orphaned packages? [Y/n]: " REMOVE_ORPHANS
        
        if [[ "$REMOVE_ORPHANS" != "n" && "$REMOVE_ORPHANS" != "N" ]]; then
            info "Removing orphaned packages..."
            apt-get autoremove -y -qq || warn "Some orphaned packages could not be removed."
        fi
    else
        success "No orphaned packages found to remove."
    fi
    
    # Clean package cache
    info "Cleaning package cache..."
    apt-get autoclean -qq || warn "Package cache cleanup failed."
    apt-get clean -qq || warn "Package cache cleaning failed."
    
    # Show disk space savings
    info "Disk space optimization completed."
    df -h / | tail -1 | awk '{print "Current disk usage: " $3 "/" $2 " (" $5 " used)"}'
else
    success "System cleanup skipped as requested."
fi

#############################################################
# Update Summary File
#############################################################

# Update summary file to include new options
cat >> "$SUMMARY_FILE" << EOF

ADDITIONAL CONFIGURATION:
------------------------
$(if [[ "$ENABLE_AUTO_UPDATES" != "n" && "$ENABLE_AUTO_UPDATES" != "N" ]]; then echo "✓ Automatic security updates enabled (${AUTO_UPDATE_FREQUENCY})"; else echo "✗ Automatic updates disabled"; fi)
$(if [[ "$RUN_CLEANUP" != "n" && "$RUN_CLEANUP" != "N" ]]; then echo "✓ System optimization completed"; else echo "✗ System cleanup was skipped"; fi)
EOF

# Final reminder
log_section "IMPORTANT SECURITY REMINDER"
warn "Make sure to save your SSH private keys and delete them from the server!"
warn "SSH is now configured on port $SSH_PORT - make note of this!"
warn "Your new admin user is: $NEW_USER"

#############################################################
# Final SSH Configuration and Restart
#############################################################
log_section "Applying SSH Configuration"
info "Restarting SSH service with new configuration..."
info "IMPORTANT: Your connection may be interrupted if you're connected via SSH."
info "Reconnect using: ssh -i /path/to/key -p $SSH_PORT $NEW_USER@your_server_ip"

# Restart SSH service as the very last step
systemctl restart sshd
success "SSH service restarted with new configuration."

exit 0
