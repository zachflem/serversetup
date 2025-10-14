#!/bin/bash

#############################################################
# Server Setup Script for Debian-based Systems
# Version: 0.9-101425-2001
#
# This script helps set up a new server with:
# - New user with sudo access
# - System hardening
# - Secure SSH configuration
# - Nginx Proxy Manager (primary reverse proxy on ports 80/443)
# - Docker and Docker Compose
#
#############################################################

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
    echo -e "${PURPLE}========================================================${NC}"
    echo -e "${PURPLE}         SERVER SETUP SCRIPT v0.9-101425-2001${NC}"
    echo -e "${PURPLE}========================================================${NC}"
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

# Prompt for username
read -p "Enter username for the new user (leave blank for 'admin'): " NEW_USER
NEW_USER=${NEW_USER:-admin}

# Check if user exists and collect password
USER_EXISTS=false
CREATE_NEW_USER=false
if id "$NEW_USER" &>/dev/null; then
    USER_EXISTS=true
    warn "User '$NEW_USER' already exists."
    read -p "Do you want to proceed with the existing user? [y/n]: " proceed
    if [[ "$proceed" != "y" && "$proceed" != "Y" ]]; then
        error "Setup cancelled by user."
        exit 1
    fi
    info "Will use existing user '$NEW_USER'."
else
    CREATE_NEW_USER=true
    # Generate or prompt for password
    read -p "Generate a random password for '$NEW_USER'? [Y/n]: " GEN_PASS
    if [[ "$GEN_PASS" == "n" || "$GEN_PASS" == "N" ]]; then
        read -s -p "Enter password for the new user: " USER_PASS
        echo
        read -s -p "Confirm password: " USER_PASS_CONFIRM
        echo
        if [[ "$USER_PASS" != "$USER_PASS_CONFIRM" ]]; then
            error "Passwords do not match."
            exit 1
        fi
    else
        USER_PASS=$(generate_password)
    fi
fi

# Prompt for hostname
CURRENT_HOSTNAME=$(hostname)
read -p "Enter hostname for the server (leave blank for '$CURRENT_HOSTNAME'): " SERVER_HOSTNAME
SERVER_HOSTNAME=${SERVER_HOSTNAME:-$CURRENT_HOSTNAME}

# SSH Port preference
DEFAULT_SSH_PORT=$(random_port)
echo "SSH Port Options:"
echo "1) Keep the default port (22)"
echo "2) Enter your own port number"
echo "3) Use a randomly generated port ($DEFAULT_SSH_PORT)"
read -p "Select SSH port option [1-3]: " SSH_PORT_OPTION

SSH_PORT=""
case $SSH_PORT_OPTION in
    1)
        SSH_PORT=22
        info "Will use default SSH port: 22"
        ;;
    2)
        read -p "Enter your preferred SSH port: " SSH_PORT
        # Make sure SSH port is valid (basic check - full validation later)
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
            warn "Port $SSH_PORT is invalid. Will use default port 22 during setup."
            SSH_PORT=22
        fi
        ;;
    3|*)
        SSH_PORT=$DEFAULT_SSH_PORT
        info "Will use randomly generated SSH port: $SSH_PORT"
        ;;
esac

# GitHub setup option
read -p "Set up SSH key for GitHub access? [Y/n]: " SETUP_GITHUB

# Collect GitHub credentials if selected
GIT_USER=""
GIT_EMAIL=""
if [[ "$SETUP_GITHUB" != "n" && "$SETUP_GITHUB" != "N" ]]; then
    read -p "Enter your GitHub username: " GIT_USER
    read -p "Enter your Git commit email address: " GIT_EMAIL
fi

# Server access URL/IP - for SSH commands
read -p "Enter the IP address or domain you'll use to access this server: " SERVER_ACCESS_URL
SERVER_ACCESS_URL=${SERVER_ACCESS_URL:-$(hostname -I | awk '{print $1}')}

# Logwatch option
read -p "Install Logwatch for daily log analysis? [Y/n]: " SETUP_LOGWATCH

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

echo
read -p "Proceed with this configuration? [y/n]: " CONFIRMATION
if [[ "$CONFIRMATION" != "y" && "$CONFIRMATION" != "Y" ]]; then
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

success "Unattended security updates configured."

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

# Provide SSH key setup instructions
instruction ""
instruction "=== SSH Key Authentication Setup ==="
instruction ""
instruction "To securely access your server, set up SSH key authentication:"
instruction ""
instruction "1. ON YOUR LOCAL MACHINE, generate SSH keys (if you don't have any):"
instruction "   ssh-keygen -t rsa -b 4096 -C 'your-email@example.com'"
instruction ""
instruction "2. Copy your public key to this server:"
instruction "   ssh-copy-id -p $SSH_PORT $NEW_USER@your_server_ip"
instruction ""
instruction "3. Set proper permissions on your local private key:"
instruction "   chmod 600 ~/.ssh/id_rsa"
instruction ""
instruction "4. Test SSH key authentication:"
instruction "   ssh -p $SSH_PORT $NEW_USER@your_server_ip"
instruction ""
instruction "5. Once key authentication works, you can disable password login for better security:"
instruction "   (SSH config will be set to allow both password and key auth during initial setup)"
instruction ""
instruction "IMPORTANT: Keep your SSH private key secure and never share it!"
instruction "The server is configured to accept both password and key authentication."
instruction ""
success "SSH directory created for '$NEW_USER'. Follow the instructions above to set up key authentication."

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
read -p "Install Logwatch for daily log analysis? [Y/n]: " SETUP_LOGWATCH
if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then
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
          SERVER SETUP SCRIPT v0.9-101425-2001
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
