#!/bin/bash

# Source required files
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/functions.sh"

#############################################################
# System Detection Functions
#############################################################

# Detect package manager and set system-specific variables
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            "ubuntu"|"debian")
                PACKAGE_MANAGER="apt-get"
                INSTALL_CMD="$PACKAGE_MANAGER install -y -qq"
                UPDATE_CMD="$PACKAGE_MANAGER update -qq"
                UPGRADE_CMD="$PACKAGE_MANAGER upgrade -y -qq"
                REMOVE_CMD="$PACKAGE_MANAGER remove -y"
                CLEAN_CMD="$PACKAGE_MANAGER clean"
                debug "Detected Debian-based system: $PRETTY_NAME"
                ;;
            "centos"|"rhel"|"fedora")
                PACKAGE_MANAGER="dnf"
                INSTALL_CMD="$PACKAGE_MANAGER install -y"
                UPDATE_CMD="$PACKAGE_MANAGER check-update"
                UPGRADE_CMD="$PACKAGE_MANAGER upgrade -y"
                REMOVE_CMD="$PACKAGE_MANAGER remove -y"
                CLEAN_CMD="$PACKAGE_MANAGER clean all"
                debug "Detected RedHat-based system: $PRETTY_NAME"
                ;;
            *)
                error "Unsupported Linux distribution: $PRETTY_NAME"
                return 1
                ;;
        esac
        
        # Export variables for use in main script
        export PACKAGE_MANAGER INSTALL_CMD UPDATE_CMD UPGRADE_CMD REMOVE_CMD CLEAN_CMD
        return 0
    else
        error "Could not determine Linux distribution"
        return 1
    fi
}

# Install packages based on detected system
install_packages() {
    local packages=("$@")
    
    # Map generic package names to distribution-specific names
    local mapped_packages=()
    for pkg in "${packages[@]}"; do
        case "$ID" in
            "ubuntu"|"debian")
                mapped_packages+=("$pkg")
                ;;
            "centos"|"rhel"|"fedora")
                case "$pkg" in
                    "ufw") mapped_packages+=("firewalld") ;;
                    "apache2") mapped_packages+=("httpd") ;;
                    *) mapped_packages+=("$pkg") ;;
                esac
                ;;
        esac
    done
    
    info "Installing packages: ${mapped_packages[*]}"
    if ! $INSTALL_CMD "${mapped_packages[@]}"; then
        error "Failed to install packages"
        return 1
    fi
    
    success "Packages installed successfully"
    return 0
}

# Configure firewall based on detected system
configure_firewall() {
    local port="$1"
    local protocol="${2:-tcp}"
    local comment="$3"
    
    case "$PACKAGE_MANAGER" in
        "apt-get")
            if ! command -v ufw &>/dev/null; then
                install_packages ufw
            fi
            ufw allow "$port"/"$protocol" ${comment:+comment "$comment"}
            ;;
        "dnf")
            if ! command -v firewall-cmd &>/dev/null; then
                install_packages firewalld
                systemctl enable firewalld
                systemctl start firewalld
            fi
            firewall-cmd --permanent --add-port="$port"/"$protocol"
            firewall-cmd --reload
            ;;
    esac
}

# Configure system services based on detected system
configure_service() {
    local service="$1"
    local action="$2"
    
    case "$PACKAGE_MANAGER" in
        "apt-get")
            systemctl "$action" "$service"
            ;;
        "dnf")
            case "$service" in
                "ufw") service="firewalld" ;;
                "apache2") service="httpd" ;;
            esac
            systemctl "$action" "$service"
            ;;
    esac
}

# Configure system repositories based on detected system
configure_repos() {
    case "$PACKAGE_MANAGER" in
        "apt-get")
            # Configure APT repositories
            if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
                install_packages ca-certificates curl gnupg lsb-release
                mkdir -p /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
            fi
            ;;
        "dnf")
            # Configure DNF repositories
            if [[ ! -f /etc/yum.repos.d/docker-ce.repo ]]; then
                dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
            fi
            ;;
    esac
}

# System-specific cleanup operations
system_cleanup() {
    case "$PACKAGE_MANAGER" in
        "apt-get")
            apt-get autoremove -y
            apt-get clean
            ;;
        "dnf")
            dnf autoremove -y
            dnf clean all
            ;;
    esac
}

# Configure system time and NTP based on detected system
configure_time() {
    local timezone="$1"
    
    # Set timezone
    if [[ -n "$timezone" ]]; then
        timedatectl set-timezone "$timezone"
    fi
    
    # Install and configure NTP
    case "$PACKAGE_MANAGER" in
        "apt-get")
            install_packages systemd-timesyncd
            systemctl enable systemd-timesyncd
            systemctl start systemd-timesyncd
            ;;
        "dnf")
            install_packages chrony
            systemctl enable chronyd
            systemctl start chronyd
            ;;
    esac
}

# Configure system limits based on detected system
configure_limits() {
    local nofile_limit="65535"
    local nproc_limit="65535"
    
    # Configure system-wide limits
    cat > /etc/security/limits.d/99-custom.conf << EOF
* soft nofile $nofile_limit
* hard nofile $nofile_limit
* soft nproc $nproc_limit
* hard nproc $nproc_limit
EOF
    
    # Configure systemd limits if applicable
    if [[ -d /etc/systemd/system.conf.d ]]; then
        cat > /etc/systemd/system.conf.d/99-custom.conf << EOF
[Manager]
DefaultLimitNOFILE=$nofile_limit
DefaultLimitNPROC=$nproc_limit
EOF
        systemctl daemon-reload
    fi
}

# Configure system logging based on detected system
configure_logging() {
    case "$PACKAGE_MANAGER" in
        "apt-get")
            install_packages rsyslog
            systemctl enable rsyslog
            systemctl start rsyslog
            ;;
        "dnf")
            install_packages rsyslog
            systemctl enable rsyslog
            systemctl start rsyslog
            ;;
    esac
    
    # Configure log rotation
    cat > /etc/logrotate.d/custom << EOF
/var/log/custom/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
}

# Configure swap based on system memory
configure_swap() {
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    local swap_size
    
    # Calculate swap size based on memory
    if [[ $mem_total -le 2048 ]]; then
        swap_size=$((mem_total * 2))
    elif [[ $mem_total -le 8192 ]]; then
        swap_size=$mem_total
    else
        swap_size=8192
    fi
    
    # Create swap file if it doesn't exist
    if [[ ! -f /swapfile ]]; then
        dd if=/dev/zero of=/swapfile bs=1M count=$swap_size
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
}

# Configure system hostname and hosts file
configure_hostname() {
    local hostname="$1"
    local ip="$2"
    
    # Set hostname
    hostnamectl set-hostname "$hostname"
    
    # Update hosts file
    if ! grep -q "$hostname" /etc/hosts; then
        echo "$ip $hostname" >> /etc/hosts
    fi
}

# Configure system network settings
configure_network() {
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-network.conf
    
    # Configure TCP settings
    cat >> /etc/sysctl.d/99-network.conf << EOF
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_tw_buckets = 4096
EOF
    
    sysctl --system
}
