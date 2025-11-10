#!/bin/bash

# Source required files
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/functions.sh"
source "$SCRIPT_DIR/system_ops.sh"

#############################################################
# Docker Installation and Management
#############################################################

# Install Docker and Docker Compose
install_docker() {
    info "Installing Docker and Docker Compose..."
    
    # Configure Docker repository
    configure_repos
    
    # Update package lists
    $UPDATE_CMD
    
    # Install Docker packages
    local docker_packages=(
        "docker-ce"
        "docker-ce-cli"
        "containerd.io"
        "docker-buildx-plugin"
        "docker-compose-plugin"
    )
    
    install_packages "${docker_packages[@]}" || return 1
    
    # Start and enable Docker service
    configure_service docker enable
    configure_service docker start
    
    # Verify Docker installation
    if ! docker version &>/dev/null; then
        error "Docker installation verification failed"
        return 1
    fi
    
    success "Docker installed successfully"
    return 0
}

# Configure Docker daemon
configure_docker() {
    info "Configuring Docker daemon..."
    
    # Create Docker daemon configuration directory
    mkdir -p /etc/docker
    
    # Configure Docker daemon
    cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "live-restore": true,
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,
    "storage-driver": "overlay2",
    "metrics-addr": "0.0.0.0:9323",
    "experimental": true
}
EOF
    
    # Restart Docker service to apply changes
    configure_service docker restart
    
    success "Docker daemon configured"
}

# Configure Docker user permissions
configure_docker_user() {
    local username="$1"
    
    info "Configuring Docker permissions for user: $username"
    
    # Create docker group if it doesn't exist
    if ! getent group docker >/dev/null; then
        groupadd docker
    fi
    
    # Add user to docker group
    usermod -aG docker "$username"
    
    success "Docker permissions configured for user: $username"
}

# Install Docker Compose
install_docker_compose() {
    info "Installing Docker Compose..."
    
    # Check if Docker Compose plugin is already installed
    if docker compose version &>/dev/null; then
        success "Docker Compose plugin already installed"
        return 0
    fi
    
    # Install Docker Compose plugin
    case "$PACKAGE_MANAGER" in
        "apt-get")
            install_packages docker-compose-plugin
            ;;
        "dnf")
            install_packages docker-compose-plugin
            ;;
    esac
    
    # Verify installation
    if ! docker compose version &>/dev/null; then
        error "Docker Compose installation failed"
        return 1
    fi
    
    success "Docker Compose installed successfully"
    return 0
}

#############################################################
# Nginx Proxy Manager Functions
#############################################################

# Install and configure Nginx Proxy Manager
install_npm() {
    local data_dir="$1"
    local admin_email="$2"
    local admin_password="$3"
    
    info "Installing Nginx Proxy Manager..."
    
    # Create required directories
    mkdir -p "$data_dir"/{data,letsencrypt}
    
    # Create Docker Compose file
    cat > "$data_dir/docker-compose.yml" << EOF
version: '3'
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
      FORCE_HTTPS: 'false'
      DISABLE_HTTPS: 'false'
    healthcheck:
      test: ["CMD", "/bin/check-health"]
      interval: 30s
      timeout: 3s
      retries: 3
    networks:
      - npm_net

networks:
  npm_net:
    driver: bridge
EOF
    
    # Set proper permissions
    chmod 600 "$data_dir/docker-compose.yml"
    chown -R "$SUDO_USER:$SUDO_USER" "$data_dir"
    
    # Start Nginx Proxy Manager
    cd "$data_dir"
    if ! docker compose up -d; then
        error "Failed to start Nginx Proxy Manager"
        return 1
    fi
    
    # Wait for NPM to initialize
    info "Waiting for Nginx Proxy Manager to initialize..."
    local retries=0
    local max_retries=30
    while ! curl -s http://localhost:81 >/dev/null; do
        sleep 2
        ((retries++))
        if [[ $retries -ge $max_retries ]]; then
            error "Nginx Proxy Manager failed to start"
            return 1
        fi
    done
    
    success "Nginx Proxy Manager installed successfully"
    
    # Configure admin user if credentials provided
    if [[ -n "$admin_email" && -n "$admin_password" ]]; then
        configure_npm_admin "$admin_email" "$admin_password"
    fi
    
    return 0
}

# Configure Nginx Proxy Manager admin user
configure_npm_admin() {
    local email="$1"
    local password="$2"
    
    info "Configuring Nginx Proxy Manager admin user..."
    
    # Wait for database to be ready
    sleep 10
    
    # Update admin user in database
    docker compose exec -T npm sqlite3 /data/database.sqlite << EOF
UPDATE users 
SET email='$email', 
    name='Administrator', 
    password='$(echo -n "$password" | sha256sum | awk '{print $1}')'
WHERE id=1;
EOF
    
    success "Admin user configured"
}

# Backup Nginx Proxy Manager data
backup_npm() {
    local data_dir="$1"
    local backup_dir="$DEFAULT_BACKUP_DIR/npm"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    info "Backing up Nginx Proxy Manager data..."
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    # Stop NPM containers
    cd "$data_dir"
    docker compose down
    
    # Create backup archive
    tar -czf "$backup_dir/npm_backup_$timestamp.tar.gz" data letsencrypt
    
    # Restart NPM containers
    docker compose up -d
    
    success "Backup created: $backup_dir/npm_backup_$timestamp.tar.gz"
}

# Restore Nginx Proxy Manager data
restore_npm() {
    local data_dir="$1"
    local backup_file="$2"
    
    info "Restoring Nginx Proxy Manager data..."
    
    # Verify backup file exists
    if [[ ! -f "$backup_file" ]]; then
        error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Stop NPM containers
    cd "$data_dir"
    docker compose down
    
    # Backup current data
    local timestamp=$(date +%Y%m%d_%H%M%S)
    tar -czf "npm_data_backup_before_restore_$timestamp.tar.gz" data letsencrypt
    
    # Remove current data
    rm -rf data letsencrypt
    
    # Extract backup
    tar -xzf "$backup_file"
    
    # Start NPM containers
    docker compose up -d
    
    success "Nginx Proxy Manager data restored"
}

# Update Nginx Proxy Manager
update_npm() {
    local data_dir="$1"
    
    info "Updating Nginx Proxy Manager..."
    
    # Pull latest image
    cd "$data_dir"
    docker compose pull
    
    # Restart containers
    docker compose down
    docker compose up -d
    
    success "Nginx Proxy Manager updated"
}

# Check Nginx Proxy Manager health
check_npm_health() {
    local data_dir="$1"
    
    info "Checking Nginx Proxy Manager health..."
    
    # Check container status
    cd "$data_dir"
    if ! docker compose ps | grep -q "Up"; then
        error "Nginx Proxy Manager container is not running"
        return 1
    fi
    
    # Check web interface
    if ! curl -s http://localhost:81 >/dev/null; then
        error "Nginx Proxy Manager web interface is not responding"
        return 1
    fi
    
    success "Nginx Proxy Manager is healthy"
    return 0
}

# Configure Nginx Proxy Manager SSL settings
configure_npm_ssl() {
    local data_dir="$1"
    local email="$2"
    
    info "Configuring Nginx Proxy Manager SSL settings..."
    
    # Update SSL settings in database
    cd "$data_dir"
    docker compose exec -T npm sqlite3 /data/database.sqlite << EOF
UPDATE settings 
SET value='{"ssl_policy":"Mozilla-Modern","hsts_enabled":true,"hsts_subdomains":true,"email":"$email"}'
WHERE key='ssl';
EOF
    
    success "SSL settings configured"
}

# Add proxy host to Nginx Proxy Manager
add_proxy_host() {
    local domain="$1"
    local target="$2"
    local ssl="${3:-false}"
    
    info "Adding proxy host: $domain -> $target"
    
    # Add proxy host to database
    docker compose exec -T npm sqlite3 /data/database.sqlite << EOF
INSERT INTO proxy_hosts 
(domain_names, forward_scheme, forward_host, forward_port, access_list_id, certificate_id, ssl_forced, caching_enabled, block_exploits, advanced_config, enabled, meta)
VALUES 
('["$domain"]', 'http', '$target', 80, 0, 0, $ssl, 0, 1, '', 1, '{"letsencrypt_agree":false,"dns_challenge":false}');
EOF
    
    success "Proxy host added"
}
