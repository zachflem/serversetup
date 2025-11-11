#!/bin/bash

# Source configuration and functions
VALIDATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$VALIDATION_DIR/config.sh"
source "$VALIDATION_DIR/functions.sh"

#############################################################
# Input Validation Functions
#############################################################

# Validate username
validate_username() {
    local username="$1"
    
    # Check if username is empty
    if [[ -z "$username" ]]; then
        error "Username cannot be empty"
        return 1
    fi
    
    # Check username length (3-32 characters)
    if [[ ${#username} -lt 3 || ${#username} -gt 32 ]]; then
        error "Username must be between 3 and 32 characters"
        return 1
    fi
    
    # Check username format (alphanumeric and underscore only)
    if ! [[ "$username" =~ ^[a-zA-Z0-9_]+$ ]]; then
        error "Username can only contain letters, numbers, and underscores"
        return 1
    fi
    
    # Check if username starts with a letter
    if ! [[ "$username" =~ ^[a-zA-Z] ]]; then
        error "Username must start with a letter"
        return 1
    }
    
    return 0
}

# Validate password strength
validate_password() {
    local password="$1"
    local min_length=12
    
    # Check password length
    if [[ ${#password} -lt $min_length ]]; then
        error "Password must be at least $min_length characters long"
        return 1
    fi
    
    # Check for uppercase letters
    if ! [[ "$password" =~ [A-Z] ]]; then
        error "Password must contain at least one uppercase letter"
        return 1
    fi
    
    # Check for lowercase letters
    if ! [[ "$password" =~ [a-z] ]]; then
        error "Password must contain at least one lowercase letter"
        return 1
    fi
    
    # Check for numbers
    if ! [[ "$password" =~ [0-9] ]]; then
        error "Password must contain at least one number"
        return 1
    fi
    
    # Check for special characters
    if ! [[ "$password" =~ [!@#\$%^&*()_+\-=\[\]{};:,.<>?] ]]; then
        error "Password must contain at least one special character"
        return 1
    fi
    
    return 0
}

# Validate hostname
validate_hostname() {
    local hostname="$1"
    
    # Check hostname length
    if [[ ${#hostname} -gt 253 ]]; then
        error "Hostname too long (max 253 characters)"
        return 1
    fi
    
    # Check hostname format
    if ! [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$ ]]; then
        error "Invalid hostname format"
        return 1
    fi
    
    return 0
}

# Validate IP address
validate_ip() {
    local ip="$1"
    
    # IPv4 validation
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -lt 0 || $i -gt 255 ]]; then
                error "Invalid IPv4 address"
                return 1
            fi
        done
    else
        error "Invalid IP address format"
        return 1
    fi
    
    return 0
}

# Validate port number
validate_port() {
    local port="$1"
    local min_port="${2:-1}"
    local max_port="${3:-65535}"
    
    # Check if port is a number
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        error "Port must be a number"
        return 1
    fi
    
    # Check port range
    if [[ $port -lt $min_port || $port -gt $max_port ]]; then
        error "Port must be between $min_port and $max_port"
        return 1
    fi
    
    return 0
}

# Validate email address
validate_email() {
    local email="$1"
    
    # Basic email format validation
    if ! [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "Invalid email address format"
        return 1
    fi
    
    return 0
}

# Validate URL
validate_url() {
    local url="$1"
    
    # Basic URL format validation
    if ! [[ "$url" =~ ^https?:// ]]; then
        error "URL must start with http:// or https://"
        return 1
    fi
    
    # Check URL validity using curl
    if ! curl --output /dev/null --silent --head --fail "$url"; then
        error "URL is not accessible"
        return 1
    fi
    
    return 0
}

# Validate file path
validate_path() {
    local path="$1"
    local check_exists="${2:-false}"
    
    # Check if path is empty
    if [[ -z "$path" ]]; then
        error "Path cannot be empty"
        return 1
    fi
    
    # Check if path contains invalid characters
    if [[ "$path" =~ [^a-zA-Z0-9_/\.-] ]]; then
        error "Path contains invalid characters"
        return 1
    fi
    
    # Check if path exists (if required)
    if [[ "$check_exists" == "true" && ! -e "$path" ]]; then
        error "Path does not exist: $path"
        return 1
    fi
    
    return 0
}

# Validate yes/no input
validate_yes_no() {
    local input="$1"
    
    case "${input,,}" in
        y|yes|true|1) return 0 ;;
        n|no|false|0) return 0 ;;
        *)
            error "Invalid input. Please enter yes or no"
            return 1
            ;;
    esac
}

# Validate SSH key type
validate_ssh_key_type() {
    local key_type="$1"
    
    case "$key_type" in
        rsa|ed25519|ecdsa) return 0 ;;
        *)
            error "Invalid SSH key type. Supported types: rsa, ed25519, ecdsa"
            return 1
            ;;
    esac
}

# Validate log level
validate_log_level() {
    local level="$1"
    
    case "${level^^}" in
        DEBUG|INFO|WARN|ERROR) return 0 ;;
        *)
            error "Invalid log level. Supported levels: DEBUG, INFO, WARN, ERROR"
            return 1
            ;;
    esac
}

# Validate update frequency
validate_update_frequency() {
    local frequency="$1"
    
    case "${frequency,,}" in
        daily|weekly|monthly) return 0 ;;
        *)
            error "Invalid update frequency. Supported values: daily, weekly, monthly"
            return 1
            ;;
    esac
}

# Validate configuration
validate_config() {
    local config_file="$1"
    
    # Load configuration
    if ! source "$config_file" 2>/dev/null; then
        error "Failed to load configuration file"
        return 1
    fi
    
    # Validate required settings
    validate_port "$DEFAULT_SSH_PORT" || return 1
    validate_username "$DEFAULT_USER" || return 1
    validate_hostname "$DEFAULT_HOSTNAME" || return 1
    validate_path "$DEFAULT_LOG_DIR" || return 1
    validate_path "$DEFAULT_BACKUP_DIR" || return 1
    validate_ssh_key_type "$SSH_KEY_TYPE" || return 1
    validate_yes_no "$PASSWORD_AUTH" || return 1
    validate_log_level "$LOG_LEVEL" || return 1
    
    # Validate optional settings if present
    [[ -n "$NOTIFICATION_EMAIL" ]] && validate_email "$NOTIFICATION_EMAIL" || return 1
    [[ -n "$UPDATE_FREQUENCY" ]] && validate_update_frequency "$UPDATE_FREQUENCY" || return 1
    
    return 0
}
