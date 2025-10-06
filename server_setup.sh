#!/bin/bash

#############################################################
# Server Setup Script for Debian-based Systems
# Version: 1.0
# 
# This script helps set up a new server with:
# - New user with sudo access
# - System hardening
# - Secure SSH configuration
# - Nginx reverse proxy
# - GitHub access
#############################################################

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging setup
LOGFILE="/var/log/server_setup.log"
mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null
touch "$LOGFILE" 2>/dev/null

# Functions
log() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} - $1" | tee -a "$LOGFILE"
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
log_section "Starting Server Setup"
check_root
check_os

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

#############################################################
# User Management
#############################################################
log_section "User Management"

instruction "You will now create a new user with sudo access."
instruction "This user will be used for administrative tasks instead of root."

# Prompt for username
read -p "Enter username for the new user (leave blank for 'admin'): " NEW_USER
NEW_USER=${NEW_USER:-admin}

# Check if user exists
if id "$NEW_USER" &>/dev/null; then
    warn "User '$NEW_USER' already exists."
    read -p "Do you want to proceed with the existing user? [y/n]: " proceed
    if [[ "$proceed" != "y" && "$proceed" != "Y" ]]; then
        error "Aborted by user."
        exit 1
    fi
else
    # Generate or prompt for password
    read -p "Generate a random password? [Y/n]: " GEN_PASS
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

    # Create user
    info "Creating new user '$NEW_USER'..."
    useradd -m -s /bin/bash "$NEW_USER" || { error "Failed to create user."; exit 1; }
    echo "$NEW_USER:$USER_PASS" | chpasswd || { error "Failed to set password."; exit 1; }
    
    # Add user to sudo group
    usermod -aG sudo "$NEW_USER" || { error "Failed to add user to sudo group."; exit 1; }
    success "User '$NEW_USER' created and added to the sudo group."
    
    if [[ "$GEN_PASS" != "n" && "$GEN_PASS" != "N" ]]; then
        info "Generated password for '$NEW_USER': $USER_PASS"
        instruction "IMPORTANT: Save this password immediately! It won't be shown again."
    fi
fi

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

# Generate random SSH port for later use
DEFAULT_SSH_PORT=$(random_port)

# Ask user for SSH port preference
echo "SSH Port Options:"
echo "1) Keep the default port (22)"
echo "2) Enter your own port number"
echo "3) Use a randomly generated port ($DEFAULT_SSH_PORT)"
read -p "Select an option [1-3]: " SSH_PORT_OPTION

case $SSH_PORT_OPTION in
    1)
        SSH_PORT=22
        info "Using default SSH port: 22"
        ;;
    2)
        read -p "Enter your preferred SSH port: " SSH_PORT
        # Make sure SSH port is valid
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1024 ] || [ "$SSH_PORT" -gt 65535 ]; then
            warn "Invalid SSH port. Using default port 22."
            SSH_PORT=22
        fi
        info "Using SSH port: $SSH_PORT"
        ;;
    3|*)
        SSH_PORT=$DEFAULT_SSH_PORT
        info "Using randomly generated SSH port: $SSH_PORT"
        ;;
esac

# Reset and disable UFW to start fresh
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH on the configured port
ufw allow "$SSH_PORT"/tcp comment 'SSH access'

# Allow HTTP and HTTPS for Nginx
ufw allow 80/tcp comment 'HTTP for Nginx'
ufw allow 443/tcp comment 'HTTPS for Nginx'

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

# Create SSH directory for the new user if it doesn't exist
mkdir -p /home/$NEW_USER/.ssh
chmod 700 /home/$NEW_USER/.ssh
chown $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh

# Generate SSH key for the new user
info "Generating SSH key pair for user '$NEW_USER'..."
SSH_KEY_FILE="/home/$NEW_USER/.ssh/id_rsa"
ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_FILE" -N "" -C "$NEW_USER@$(hostname)"
chmod 600 "$SSH_KEY_FILE"
chmod 644 "$SSH_KEY_FILE.pub"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
success "SSH key pair generated for '$NEW_USER'."

# Display the private key (to be saved by the user)
info "Here is the private SSH key for user '$NEW_USER'. Save this to your local machine:"
echo
echo "------------BEGIN SSH PRIVATE KEY------------"
cat "$SSH_KEY_FILE"
echo "------------END SSH PRIVATE KEY------------"
echo

instruction "IMPORTANT: Copy this private key to your local machine and then delete it from the server!"
instruction "You can save it to a file named id_rsa, set its permissions to 600, and use it to connect with:"
instruction "ssh -i path/to/id_rsa -p $SSH_PORT $NEW_USER@your_server_ip"

# Also display the public key
info "Public SSH key for user '$NEW_USER':"
cat "$SSH_KEY_FILE.pub"
echo

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH
info "Hardening SSH configuration..."
cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration
Port $SSH_PORT
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
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
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 2
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
# Nginx Installation and Configuration
#############################################################
log_section "Nginx Installation and Configuration"

info "Installing Nginx..."
apt-get install -y -qq nginx || { error "Failed to install Nginx."; exit 1; }

info "Configuring Nginx as a reverse proxy..."
# Remove the default site configuration to avoid conflicts
if [ -f /etc/nginx/sites-enabled/default ]; then
    rm /etc/nginx/sites-enabled/default
    info "Removed default Nginx site configuration to prevent conflicts."
fi

# Create a better default Nginx configuration
cat > /etc/nginx/conf.d/default.conf << EOF
# Security headers
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Redirect all HTTP to HTTPS (uncomment after setting up SSL)
    # return 301 https://\$host\$request_uri;

    # Temporary landing page
    root /var/www/html;
    index index.html index.htm;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'self'; frame-ancestors 'self'; form-action 'self';";
    add_header Referrer-Policy no-referrer-when-downgrade;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Reverse proxy example config (commented out)
    # location /app/ {
    #     proxy_pass http://localhost:8080/;
    #     proxy_http_version 1.1;
    #     proxy_set_header Upgrade \$http_upgrade;
    #     proxy_set_header Connection \$connection_upgrade;
    #     proxy_set_header Host \$host;
    #     proxy_set_header X-Real-IP \$remote_addr;
    #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto \$scheme;
    # }
}

# HTTPS server (uncomment after setting up SSL)
# server {
#     listen 443 ssl http2;
#     listen [::]:443 ssl http2;
#     server_name _;
#
#     ssl_certificate /etc/nginx/ssl/server.crt;
#     ssl_certificate_key /etc/nginx/ssl/server.key;
#     ssl_protocols TLSv1.2 TLSv1.3;
#     ssl_prefer_server_ciphers on;
#     ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
#     ssl_session_timeout 1d;
#     ssl_session_cache shared:SSL:10m;
#     ssl_session_tickets off;
#
#     # OCSP Stapling
#     ssl_stapling on;
#     ssl_stapling_verify on;
#
#     # Security headers (same as HTTP)
#     add_header X-Content-Type-Options nosniff;
#     add_header X-Frame-Options SAMEORIGIN;
#     add_header X-XSS-Protection "1; mode=block";
#     add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; frame-src 'self'; frame-ancestors 'self'; form-action 'self';";
#     add_header Referrer-Policy no-referrer-when-downgrade;
#     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
#
#     root /var/www/html;
#     index index.html index.htm;
#
#     # Reverse proxy example (same as HTTP)
#     # location /app/ {
#     #     proxy_pass http://localhost:8080/;
#     #     proxy_http_version 1.1;
#     #     proxy_set_header Upgrade \$http_upgrade;
#     #     proxy_set_header Connection \$connection_upgrade;
#     #     proxy_set_header Host \$host;
#     #     proxy_set_header X-Real-IP \$remote_addr;
#     #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
#     #     proxy_set_header X-Forwarded-Proto \$scheme;
#     # }
# }
EOF

# Create a simple landing page
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Server Setup Complete</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.6;
            color: #333;
        }
        h1 {
            color: #4CAF50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .info {
            background-color: #f9f9f9;
            border-left: 4px solid #4CAF50;
            padding: 15px;
            margin: 20px 0;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <h1>Server Setup Complete</h1>
    <p>Your server has been successfully set up and hardened. This is a temporary landing page served by Nginx.</p>
    
    <div class="info">
        <p><strong>Next steps:</strong></p>
        <ul>
            <li>Configure your applications to work with Nginx reverse proxy</li>
            <li>Set up SSL/TLS certificates for HTTPS</li>
            <li>Replace this page with your actual content</li>
        </ul>
    </div>
    
    <p>For more information, check the server logs and documentation.</p>
</body>
</html>
EOF

# Test Nginx configuration
info "Testing Nginx configuration..."
nginx -t
if [ $? -eq 0 ]; then
    success "Nginx configuration is valid."
    systemctl enable nginx
    systemctl restart nginx
    success "Nginx service enabled and restarted."
else
    error "Nginx configuration test failed."
    exit 1
fi

#############################################################
# GitHub Access Setup
#############################################################
log_section "GitHub Access Setup"

info "Setting up Git for user '$NEW_USER'..."

# Configure Git for the new user
su - "$NEW_USER" -c "git config --global user.name \"$NEW_USER\""
su - "$NEW_USER" -c "git config --global user.email \"$NEW_USER@$(hostname)\""

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
    su - "$NEW_USER" -c "ssh-keygen -t rsa -b 4096 -f \"$GIT_SSH_KEY\" -N \"\" -C \"$NEW_USER@$(hostname)-github\""
    
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

cat > "$SUMMARY_FILE" << EOF
========================================================
          SERVER SETUP SUMMARY
========================================================

SYSTEM INFORMATION:
------------------
Date: $(date)
Hostname: $(hostname)
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
✓ Nginx (configured as reverse proxy)
✓ Git (configured for GitHub access)
$(if [[ "$SETUP_LOGWATCH" != "n" && "$SETUP_LOGWATCH" != "N" ]]; then echo "✓ Logwatch (daily log analysis)"; fi)

FIREWALL RULES:
------------------
$(ufw status | grep -v "Status")

NEXT STEPS:
------------------
1. Save your SSH private keys to your local machine
2. Delete the private keys from the server
3. Test SSH login with: ssh -i /path/to/key -p $SSH_PORT $NEW_USER@SERVER_IP
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
