#!/bin/bash

###############################################################################
# Suricata Service User Setup Script
# This script creates a dedicated system user for Suricata
# Run this BEFORE suricata_install.sh
###############################################################################

set -e  # Exit on any error
umask 077  # Set restrictive default permissions

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
SURICATA_USER="suricata"
SURICATA_GROUP="suricata"
SURICATA_HOME="/var/lib/suricata"
LOG_FILE="/var/log/suricata_user_setup.log"

###############################################################################
# Logging Functions
###############################################################################

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

###############################################################################
# Prerequisite Checks
###############################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    log_success "Running as root"
}

###############################################################################
# User and Group Management
###############################################################################

create_suricata_user() {
    log "Creating dedicated Suricata system user and group..."

    # Check if group already exists
    if getent group "$SURICATA_GROUP" > /dev/null 2>&1; then
        log_warning "Group '$SURICATA_GROUP' already exists"
    else
        # Create system group
        if groupadd --system "$SURICATA_GROUP"; then
            log_success "Created system group: $SURICATA_GROUP"
        else
            log_error "Failed to create group: $SURICATA_GROUP"
            exit 1
        fi
    fi

    # Check if user already exists
    if id "$SURICATA_USER" &> /dev/null; then
        log_warning "User '$SURICATA_USER' already exists"

        # Ensure user has correct properties
        usermod --system \
                --home "$SURICATA_HOME" \
                --shell /usr/sbin/nologin \
                --gid "$SURICATA_GROUP" \
                --comment "Suricata IDS System User" \
                "$SURICATA_USER"
        log_success "Updated existing user: $SURICATA_USER"
    else
        # Create system user
        if useradd --system \
                   --home-dir "$SURICATA_HOME" \
                   --no-create-home \
                   --shell /usr/sbin/nologin \
                   --gid "$SURICATA_GROUP" \
                   --comment "Suricata IDS System User" \
                   "$SURICATA_USER"; then
            log_success "Created system user: $SURICATA_USER"
        else
            log_error "Failed to create user: $SURICATA_USER"
            exit 1
        fi
    fi

    # Lock the account to prevent login
    passwd -l "$SURICATA_USER" > /dev/null 2>&1
    log_success "Locked user account to prevent login"

    # Verify user creation
    if id "$SURICATA_USER" &> /dev/null; then
        USER_ID=$(id -u "$SURICATA_USER")
        GROUP_ID=$(id -g "$SURICATA_USER")
        log_success "User verification - UID: $USER_ID, GID: $GROUP_ID"
    else
        log_error "User verification failed"
        exit 1
    fi
}

###############################################################################
# Summary Report
###############################################################################

print_summary() {
    cat << EOF

${GREEN}════════════════════════════════════════════════════════════${NC}
${GREEN}  Suricata Service User Created Successfully!${NC}
${GREEN}════════════════════════════════════════════════════════════${NC}

${BLUE}User Configuration:${NC}
  • User: $SURICATA_USER (UID: $(id -u $SURICATA_USER))
  • Group: $SURICATA_GROUP (GID: $(id -g $SURICATA_GROUP))
  • Home Directory: $SURICATA_HOME (not created yet)
  • Shell: /usr/sbin/nologin (login disabled)
  • Account Status: Locked (password authentication disabled)

${BLUE}Next Steps:${NC}
  1. Run suricata_install.sh to install and configure Suricata
  2. The install script will set up all directories, permissions, and services

${BLUE}Log File:${NC}
  • $LOG_FILE

${GREEN}════════════════════════════════════════════════════════════${NC}

EOF
}

###############################################################################
# Cleanup Functions
###############################################################################

cleanup() {
    # Secure log file permissions
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE"
        chown root:adm "$LOG_FILE" 2>/dev/null || chown root:root "$LOG_FILE"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

###############################################################################
# Main Execution Flow
###############################################################################

main() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║        Suricata Service User Creation Script          ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log "Starting Suricata service user creation..."

    # Check prerequisites
    check_root

    # Create user and group
    create_suricata_user

    # Print summary
    print_summary

    log_success "Service user creation completed successfully!"
}

# Run main function
main "$@"
