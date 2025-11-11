#!/bin/bash

# Default configuration values
DEFAULT_SSH_PORT=22
DEFAULT_USER="admin"
DEFAULT_HOSTNAME=$(hostname)
DEFAULT_LOG_DIR="/var/log/server_setup"
DEFAULT_BACKUP_DIR="/var/backups/server_setup"

# Script version
if [[ -z "${SCRIPT_VERSION:-}" ]]; then
    readonly SCRIPT_VERSION="1.0.0"
fi

# Security settings
SSH_KEY_TYPE="ed25519"  # More secure than RSA
SSH_KEY_BITS="4096"
PASSWORD_AUTH="yes"  # Can be toggled to "no" after key setup
FAIL2BAN_MAX_RETRIES=3
FAIL2BAN_BANTIME=86400
FAIL2BAN_FINDTIME=600

# Docker settings
DOCKER_INSTALL="yes"
DOCKER_COMPOSE_VERSION="latest"
NPM_PORT_HTTP=80
NPM_PORT_HTTPS=443
NPM_PORT_ADMIN=81

# Monitoring settings
ENABLE_LOGWATCH="no"
ENABLE_AUTO_UPDATES="yes"
UPDATE_FREQUENCY="weekly"
EMAIL_NOTIFICATIONS="no"
NOTIFICATION_EMAIL=""

# System settings
TIMEZONE="UTC"
IPV6_DISABLE="yes"
CLEANUP_ON_EXIT="yes"
BACKUP_CONFIGS="yes"

# Logging settings
LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
LOG_MAX_SIZE="10M"
LOG_KEEP_DAYS=30
