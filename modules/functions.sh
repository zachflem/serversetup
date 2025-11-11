#!/bin/bash

# Source configuration
# Get the directory where this functions.sh file is located
FUNCTIONS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$FUNCTIONS_DIR/config.sh"

#############################################################
# Logging Functions
#############################################################

# Initialize logging
init_logging() {
    local log_dir="${1:-$DEFAULT_LOG_DIR}"
    mkdir -p "$log_dir"
    LOGFILE="$log_dir/server_setup_$(date +%Y%m%d_%H%M%S).log"
    touch "$LOGFILE"
    
    # Start log rotation
    setup_log_rotation
}

# Setup log rotation
setup_log_rotation() {
    cat > /etc/logrotate.d/server_setup << EOF
$DEFAULT_LOG_DIR/*.log {
    rotate $LOG_KEEP_DAYS
    daily
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root root
    size $LOG_MAX_SIZE
}
EOF
}

# Enhanced logging with levels
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Only log if level is sufficient
    case "$LOG_LEVEL" in
        "DEBUG") log_allowed=1 ;;
        "INFO") [[ "$level" != "DEBUG" ]] && log_allowed=1 ;;
        "WARN") [[ "$level" != "DEBUG" && "$level" != "INFO" ]] && log_allowed=1 ;;
        "ERROR") [[ "$level" == "ERROR" ]] && log_allowed=1 ;;
        *) log_allowed=0 ;;
    esac
    
    if [[ $log_allowed -eq 1 ]]; then
        echo "[$timestamp] $level: $message" >> "$LOGFILE"
        
        # Terminal output with colors
        case "$level" in
            "DEBUG") echo -e "\e[36m[DEBUG]\e[0m $message" ;;
            "INFO")  echo -e "\e[32m[INFO]\e[0m $message" ;;
            "WARN")  echo -e "\e[33m[WARN]\e[0m $message" >&2 ;;
            "ERROR") echo -e "\e[31m[ERROR]\e[0m $message" >&2 ;;
        esac
        
        # Send email notification for errors if enabled
        if [[ "$level" == "ERROR" && "$EMAIL_NOTIFICATIONS" == "yes" && -n "$NOTIFICATION_EMAIL" ]]; then
            send_notification "Server Setup Error" "$message"
        fi
    fi
}

# Shorthand logging functions
debug() { log "DEBUG" "$1"; }
info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
error() { log "ERROR" "$1"; }

#############################################################
# Error Handling Functions
#############################################################

# Enhanced error handling
handle_error() {
    local exit_code=$1
    local error_msg=$2
    local line_no=$3
    
    error "Error on line $line_no: $error_msg (Exit code: $exit_code)"
    
    if [[ "$CLEANUP_ON_EXIT" == "yes" ]]; then
        cleanup
    fi
    
    exit $exit_code
}

# Cleanup function
cleanup() {
    info "Starting cleanup process..."
    
    # Stop services if they were started
    if systemctl is-active --quiet docker; then
        systemctl stop docker
    fi
    
    # Remove temporary files
    if [[ -d "$DEFAULT_LOG_DIR/tmp" ]]; then
        rm -rf "$DEFAULT_LOG_DIR/tmp"
    fi
    
    # Restore backups if they exist
    if [[ -d "$DEFAULT_BACKUP_DIR" ]]; then
        restore_backups
    fi
    
    info "Cleanup completed"
}

# Backup function
backup_config() {
    local file="$1"
    local backup_dir="$DEFAULT_BACKUP_DIR/$(dirname "$file")"
    
    mkdir -p "$backup_dir"
    if [[ -f "$file" ]]; then
        cp "$file" "$backup_dir/$(basename "$file").bak_$(date +%Y%m%d_%H%M%S)"
        debug "Backed up $file"
    fi
}

# Restore backups
restore_backups() {
    info "Restoring configuration backups..."
    
    find "$DEFAULT_BACKUP_DIR" -name "*.bak_*" | while read backup_file; do
        local original_file=$(echo "$backup_file" | sed 's/\.bak_[0-9_]*//')
        if [[ -f "$backup_file" ]]; then
            cp "$backup_file" "$original_file"
            debug "Restored $original_file from backup"
        fi
    done
}

#############################################################
# System Check Functions
#############################################################

# Check system requirements
check_system_requirements() {
    info "Checking system requirements..."
    
    # Check OS compatibility
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            "ubuntu"|"debian")
                debug "Detected supported OS: $PRETTY_NAME"
                ;;
            *)
                error "Unsupported OS: $PRETTY_NAME"
                return 1
                ;;
        esac
    else
        error "Could not determine OS type"
        return 1
    fi
    
    # Check disk space
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [[ $free_space -lt 1024 ]]; then
        error "Insufficient disk space. At least 1GB required"
        return 1
    fi
    
    # Check memory
    local total_mem=$(free -m | awk 'NR==2 {print $2}')
    if [[ $total_mem -lt 512 ]]; then
        warn "Low memory detected. Some features may not work properly"
    fi
    
    return 0
}

# Check for required commands
check_commands() {
    local commands=("$@")
    local missing=()
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required commands: ${missing[*]}"
        return 1
    fi
    
    return 0
}

#############################################################
# Notification Functions
#############################################################

# Send notification
send_notification() {
    local subject="$1"
    local message="$2"
    
    if [[ "$EMAIL_NOTIFICATIONS" == "yes" && -n "$NOTIFICATION_EMAIL" ]]; then
        if command -v mail &> /dev/null; then
            echo "$message" | mail -s "$subject" "$NOTIFICATION_EMAIL"
            debug "Notification sent to $NOTIFICATION_EMAIL"
        else
            warn "mail command not found. Notification not sent"
        fi
    fi
}

#############################################################
# Progress Indicator Functions
#############################################################

# Start progress indicator
start_progress() {
    local message="$1"
    echo -n "$message... "
}

# End progress indicator
end_progress() {
    local status=$1
    if [[ $status -eq 0 ]]; then
        echo -e "\e[32m[OK]\e[0m"
    else
        echo -e "\e[31m[FAILED]\e[0m"
    fi
}

# Show spinner for long-running operations
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    
    while ps a | awk '{print $1}' | grep -q "$pid"; do
        local temp=${spinstr#?}
        printf "\r[%c] " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf "\r"
}

#############################################################
# Setup Functions
#############################################################

# Initialize script
init_script() {
    # Set up error handling
    set -o errexit
    set -o nounset
    set -o pipefail
    
    # Set up trap handlers
    trap 'handle_error $? "Unexpected error" $LINENO' ERR
    trap cleanup EXIT
    
    # Initialize logging
    init_logging
    
    # Create backup directory
    mkdir -p "$DEFAULT_BACKUP_DIR"
    
    # Check system requirements
    check_system_requirements || exit 1
    
    # Check required commands
    check_commands "curl" "wget" "gpg" || exit 1
    
    info "Script initialization completed"
}

# Load configuration from file
load_config() {
    local config_file="$1"
    
    if [[ -f "$config_file" ]]; then
        source "$config_file"
        debug "Loaded configuration from $config_file"
    else
        warn "Configuration file $config_file not found, using defaults"
    fi
}

# Save configuration to file
save_config() {
    local config_file="$1"
    
    mkdir -p "$(dirname "$config_file")"
    declare -p | grep -E '^declare (-r)?\ -x' > "$config_file"
    debug "Saved configuration to $config_file"
}
