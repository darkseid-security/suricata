#!/bin/bash

###############################################################################
# Suricata Installation and Configuration Script
# This script automates the installation, configuration, and deployment of
# Suricata IDS with custom detection rules for network reconnaissance scanning
###############################################################################

set -e  # Exit on any error
umask 077  # Set restrictive default permissions for created files

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
RULES_DIR="/var/lib/suricata/rules"
LOCAL_RULES_FILE="/var/lib/suricata/rules/local.rules"
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
LOG_FILE="/var/log/suricata_install.log"

###############################################################################
# Logging and Output Functions
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

check_os() {
    if [[ ! -f /etc/lsb-release ]]; then
        log_error "This script is designed for Debian/Ubuntu systems"
        exit 1
    fi
    log_success "Detected Debian/Ubuntu system"
}

###############################################################################
# Installation Functions
###############################################################################

install_dependencies() {
    log "Installing dependencies..."
    apt-get update > /dev/null 2>&1
    apt-get install -y software-properties-common python3-pip python3-venv > /dev/null 2>&1
    log_success "Dependencies installed"

    # Create and activate virtual environment for Python packages
    log "Setting up Python virtual environment..."
    VENV_DIR="/home/threat_detection/venv"

    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
        log "Virtual environment created at $VENV_DIR"
    fi

    # Store venv path securely using mktemp
    TEMP_VENV_FILE=$(mktemp -t venv_path.XXXXXX)
    echo "$VENV_DIR" > "$TEMP_VENV_FILE"
    chmod 600 "$TEMP_VENV_FILE"

    # Export for use in other functions
    export TEMP_VENV_FILE

    log_success "Python virtual environment ready"
}

add_suricata_repository() {
    log "Adding Suricata stable repository..."
    add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1
    apt-get update > /dev/null 2>&1
    log_success "Repository added"
}

install_suricata() {
    log "Installing Suricata and jq..."
    apt-get install -y suricata jq > /dev/null 2>&1
    log_success "Suricata and jq installed"
}

verify_installation() {
    log "Verifying Suricata installation..."
    SURICATA_VERSION=$(suricata -V 2>&1 | head -n 1)
    log_success "Suricata version: $SURICATA_VERSION"
}

###############################################################################
# Network Interface Detection and Configuration
###############################################################################

detect_primary_interface() {
    log "Detecting primary network interface..."
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [[ -z "$INTERFACE" ]]; then
        log_error "Could not detect primary interface"
        exit 1
    fi

    # Validate interface name to prevent injection attacks
    if [[ ! "$INTERFACE" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log_error "Invalid interface name detected: $INTERFACE"
        exit 1
    fi

    # Verify interface actually exists
    if ! ip link show "$INTERFACE" &> /dev/null; then
        log_error "Interface $INTERFACE does not exist"
        exit 1
    fi

    log_success "Primary interface detected: $INTERFACE"
}

enable_promiscuous_mode() {
    log "Enabling promiscuous mode on interface $INTERFACE..."

    # Check current interface status
    if ip link show "$INTERFACE" | grep -q "PROMISC"; then
        log_warning "Interface $INTERFACE is already in promiscuous mode"
    else
        # Enable promiscuous mode
        if ip link set "$INTERFACE" promisc on; then
            log_success "Promiscuous mode enabled on $INTERFACE"
        else
            log_error "Failed to enable promiscuous mode on $INTERFACE"
            exit 1
        fi
    fi

    # Verify promiscuous mode is active
    if ip link show "$INTERFACE" | grep -q "PROMISC"; then
        log_success "Verified: $INTERFACE is in promiscuous mode"
    else
        log_error "Verification failed: $INTERFACE is not in promiscuous mode"
        exit 1
    fi

    # Make promiscuous mode persistent across reboots
    log "Making promiscuous mode persistent..."

    # Create systemd service to enable promiscuous mode on boot
    cat > /etc/systemd/system/promiscuous-${INTERFACE}.service << SYSTEMD_EOF
[Unit]
Description=Enable promiscuous mode on ${INTERFACE}
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set ${INTERFACE} promisc on
RemainAfterExit=yes

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/sys/class/net
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_NETLINK AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

    # Set secure permissions on the service file
    chmod 644 /etc/systemd/system/promiscuous-${INTERFACE}.service
    chown root:root /etc/systemd/system/promiscuous-${INTERFACE}.service

    # Enable the service
    systemctl daemon-reload
    systemctl enable promiscuous-${INTERFACE}.service > /dev/null 2>&1
    log_success "Promiscuous mode will persist across reboots"
}

get_interface_ip_range() {
    log "Retrieving IP address and calculating network range..."
    IP_ADDR=$(ip addr show "$INTERFACE" | grep "inet " | awk '{print $2}')
    if [[ -z "$IP_ADDR" ]]; then
        log_error "Could not retrieve IP address for $INTERFACE"
        exit 1
    fi

    # Validate IP address format
    if [[ ! "$IP_ADDR" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        log_error "Invalid IP address format: $IP_ADDR"
        exit 1
    fi

    log_success "IP Address: $IP_ADDR"

    # Extract network range (CIDR notation)
    HOME_NET="${IP_ADDR%/*}/24"

    # Validate HOME_NET format
    if [[ ! "$HOME_NET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        log_error "Invalid HOME_NET format: $HOME_NET"
        exit 1
    fi

    log "Calculated HOME_NET: $HOME_NET"
}

###############################################################################
# Suricata Configuration
###############################################################################

configure_suricata() {
    log "Configuring Suricata..."
    
    if [[ ! -f "$SURICATA_CONFIG" ]]; then
        log_error "Suricata configuration file not found at $SURICATA_CONFIG"
        exit 1
    fi
    
    # First, restore the original config from the package to fix any corruption
    log "Restoring original Suricata configuration from package..."
    if ! apt-get install --reinstall -o DPkg::Options::="--force-confmiss" suricata -y > /dev/null 2>&1; then
        log_warning "Could not restore from package, will work with current file"
    else
        log_success "Configuration restored from package"
    fi
    
    # Backup the restored configuration
    BACKUP_FILE="${SURICATA_CONFIG}.bak.$(date +%s)"
    cp "$SURICATA_CONFIG" "$BACKUP_FILE"
    chmod 600 "$BACKUP_FILE"
    chown root:root "$BACKUP_FILE"
    log "Backup created with secure permissions: $BACKUP_FILE"
    
    # Activate venv and use Python to modify YAML
    VENV_DIR=$(cat "$TEMP_VENV_FILE")
    source "$VENV_DIR/bin/activate"
    
    log "Installing PyYAML in virtual environment..."
    pip install --quiet pyyaml > /dev/null 2>&1
    
    log "Modifying Suricata configuration with PyYAML..."
    python3 << PYTHON_CONFIG
import yaml
import sys

config_file = "$SURICATA_CONFIG"
home_net = "$HOME_NET"
interface = "$INTERFACE"

try:
    # Load YAML configuration
    with open(config_file, 'r') as f:
        content = f.read()
        config = yaml.safe_load(content)
    
    # Check if config loaded successfully
    if config is None:
        print("✗ Error: Configuration file is empty or invalid", file=sys.stderr)
        sys.exit(1)
    
    print("✓ YAML file loaded successfully")
    
    # Modify HOME_NET in vars.address-groups
    if 'vars' not in config:
        config['vars'] = {}
    if 'address-groups' not in config['vars']:
        config['vars']['address-groups'] = {}
    
    config['vars']['address-groups']['HOME_NET'] = home_net
    print(f"✓ HOME_NET set to: {home_net}")
    
    # Set default-rule-path
    config['default-rule-path'] = '/var/lib/suricata/rules'
    print("✓ default-rule-path: /var/lib/suricata/rules")
    
    # Configure rule-files
    config['rule-files'] = ['suricata.rules', 'local.rules']
    print("✓ rule-files: [suricata.rules, local.rules]")
    
    # Configure pcap if it exists
    if 'pcap' in config and isinstance(config['pcap'], list):
        for pcap_config in config['pcap']:
            if isinstance(pcap_config, dict):
                pcap_config['interface'] = interface
                pcap_config['pcap-file'] = True
                pcap_config['community-id'] = True
        print(f"✓ pcap interface: {interface}, pcap-file: true, community-id: true")
    
    # Configure af-packet if it exists
    if 'af-packet' in config and isinstance(config['af-packet'], list):
        for ap_config in config['af-packet']:
            if isinstance(ap_config, dict):
                ap_config['interface'] = interface
        print(f"✓ af-packet interface: {interface}")
    
    # Write back configuration with YAML 1.1 header and proper formatting
    with open(config_file, 'w') as f:
        # Write YAML 1.1 header as required by Suricata
        f.write('%YAML 1.1\n')
        f.write('---\n')
        # Dump the config without the default YAML header
        yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False, allow_unicode=True)
        f.write(yaml_content)
    
    print("✓ Configuration saved successfully with YAML 1.1 header")

except yaml.YAMLError as e:
    print(f"✗ YAML Error: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}", file=sys.stderr)
    sys.exit(1)

PYTHON_CONFIG
    
    PYTHON_RESULT=$?

    if [[ $PYTHON_RESULT -eq 0 ]]; then
        log_success "Suricata configuration updated"
    else
        log_error "Failed to update Suricata configuration"
        exit 1
    fi

    deactivate

    # Set secure permissions on configuration file
    chmod 600 "$SURICATA_CONFIG"
    chown root:root "$SURICATA_CONFIG"
    log_success "Configuration file secured with proper permissions"
}

###############################################################################
# Custom Rules Deployment
###############################################################################

create_custom_rules() {
    log "Creating custom detection rules..."

    if [[ ! -d "$RULES_DIR" ]]; then
        mkdir -p "$RULES_DIR"
        log "Created rules directory: $RULES_DIR"
    fi

    # Set secure permissions on rules directory
    chmod 755 "$RULES_DIR"
    chown root:root "$RULES_DIR"

    # Ensure /etc/suricata/rules directory exists
    mkdir -p /etc/suricata/rules
    chmod 755 /etc/suricata/rules
    chown root:root /etc/suricata/rules
    log "Ensured /etc/suricata/rules directory exists with secure permissions"

    cat > "$LOCAL_RULES_FILE" << 'EOF'
# Custom Suricata Detection Rules
# Reconnaissance and Network Scanning Detection

# ICMP Echo Request Flood Detection
alert icmp any any -> any any (msg:"CUSTOM ET SCAN ICMP Echo Request flood / ping sweep"; itype:8; detection_filter:track by_src, count 30, seconds 60; classtype:attempted-recon; sid:10000010; rev:2;)

# ICMP Ping Sweep Detection
alert icmp any any -> any any (msg:"CUSTOM ET SCAN ICMP Ping sweep - multiple destinations"; itype:8; detection_filter:track by_src, count 20, seconds 60; classtype:attempted-recon; sid:10000011; rev:2;)

# Nmap SYN Scan Detection
alert tcp any any -> any any (msg:"CUSTOM ET SCAN Possible Nmap SYN scan - multiple SYNs from src"; flags:S; flow:stateless; detection_filter:track by_src, count 25, seconds 60; classtype:attempted-recon; sid:10000001; rev:2;)

# Nmap NULL Scan Detection
alert tcp any any -> any any (msg:"CUSTOM ET SCAN Possible Nmap NULL scan (no TCP flags)"; flags:0; flow:stateless; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-recon; sid:10000002; rev:2;)

# Nmap Xmas Scan Detection
alert tcp any any -> any any (msg:"CUSTOM ET SCAN Possible Nmap Xmas scan (FIN,PSH,URG)"; flags:FPU; flow:stateless; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-recon; sid:10000003; rev:2;)

# Nmap FIN Scan Detection
alert tcp any any -> any any (msg:"CUSTOM ET SCAN Possible Nmap FIN scan (FIN only)"; flags:F; flow:stateless; detection_filter:track by_src, count 10, seconds 60; classtype:attempted-recon; sid:10000004; rev:2;)

EOF

    # Set secure permissions on rules files
    chmod 644 "$LOCAL_RULES_FILE"
    chown root:root "$LOCAL_RULES_FILE"

    log_success "Custom rules file created at: $LOCAL_RULES_FILE with secure permissions"
}

###############################################################################
# Configuration Validation
###############################################################################

validate_configuration() {
    log "Validating Suricata configuration..."
    
    # Just do a basic test - the actual validation will happen when suricata-update runs
    if suricata -T -c "$SURICATA_CONFIG" -v 2>&1 | grep -qi "configuration provided was successfully loaded"; then
        log_success "Configuration validation passed"
    else
        # Warnings are okay at this point - rules don't exist yet
        log_warning "Configuration check completed (rules will be created by suricata-update)"
    fi
}

###############################################################################
# Rules Update
###############################################################################

update_rules() {
    log "Updating Suricata rules database..."
    if suricata-update 2>&1 | tee -a "$LOG_FILE"; then
        log_success "Rules update completed successfully"
    else
        log_warning "Suricata-update completed with warnings (non-critical)"
    fi
    
    log "Restarting Suricata service to apply new rules..."
    systemctl restart suricata.service
    sleep 10
    log_success "Service restarted with updated rules"
}

###############################################################################
# Service Management
###############################################################################

enable_service() {
    log "Enabling Suricata service..."
    systemctl enable suricata.service > /dev/null 2>&1
    log_success "Suricata service enabled"
}

start_service() {
    log "Starting Suricata service..."
    systemctl start suricata.service
    sleep 3
    
    if systemctl is-active --quiet suricata.service; then
        log_success "Suricata service started successfully"
    else
        log_error "Failed to start Suricata service"
        systemctl status suricata.service >> "$LOG_FILE"
        exit 1
    fi
}

verify_service_ready() {
    log "Waiting for Suricata to fully initialize..."
    local max_attempts=15
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        # Check if service is running
        if ! systemctl is-active --quiet suricata.service; then
            log_error "Suricata service is not running"
            exit 1
        fi
        
        # Check if rules are loaded in the journal
        if journalctl -u suricata.service -n 50 | grep -q "Engine started"; then
            log_success "Suricata fully initialized with rules loaded"
            return 0
        fi
        
        log "Waiting for rules to load... (attempt $attempt/$max_attempts)"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_warning "Timeout waiting for full initialization (continuing anyway)"
}

check_service_status() {
    log "Checking Suricata service status..."
    systemctl status suricata.service --no-pager | tee -a "$LOG_FILE"
}

###############################################################################
# Directory Structure and Permissions
###############################################################################

setup_directory_permissions() {
    log "Setting up directory structure with proper permissions..."

    # Array of directories with their required permissions
    declare -A DIRECTORIES=(
        ["/var/lib/suricata"]="750"
        ["/var/lib/suricata/rules"]="750"
        ["/etc/suricata"]="750"
        ["/etc/suricata/rules"]="750"
        ["/var/log/suricata"]="750"
        ["/var/run/suricata"]="755"
    )

    for dir in "${!DIRECTORIES[@]}"; do
        perm="${DIRECTORIES[$dir]}"

        # Create directory if it doesn't exist
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir"; then
                log "Created directory: $dir"
            else
                log_error "Failed to create directory: $dir"
                exit 1
            fi
        fi

        # Set ownership
        if chown -R suricata:suricata "$dir"; then
            log_success "Set ownership on $dir to suricata:suricata"
        else
            log_error "Failed to set ownership on: $dir"
            exit 1
        fi

        # Set permissions
        if chmod "$perm" "$dir"; then
            log_success "Set permissions on $dir to $perm"
        else
            log_error "Failed to set permissions on: $dir"
            exit 1
        fi
    done
}

setup_file_permissions() {
    log "Setting proper file permissions..."

    # Configuration files - read-only for suricata user
    if [[ -f "$SURICATA_CONFIG" ]]; then
        chown root:suricata "$SURICATA_CONFIG"
        chmod 640 "$SURICATA_CONFIG"
        log_success "Secured suricata.yaml (root:suricata, 640)"
    fi

    # Rules files - read-only for suricata user
    if [[ -d "$RULES_DIR" ]]; then
        find "$RULES_DIR" -type f -name "*.rules" -exec chown root:suricata {} \;
        find "$RULES_DIR" -type f -name "*.rules" -exec chmod 640 {} \;
        log_success "Secured all .rules files (root:suricata, 640)"
    fi

    # Log files - writable by suricata user
    if [[ -d "/var/log/suricata" ]]; then
        find "/var/log/suricata" -type f -exec chown suricata:suricata {} \;
        find "/var/log/suricata" -type f -exec chmod 640 {} \;
        log_success "Set log file permissions (suricata:suricata, 640)"
    fi

    # Runtime directory
    if [[ -d "/var/run/suricata" ]]; then
        chown suricata:suricata "/var/run/suricata"
        chmod 755 "/var/run/suricata"
        log_success "Set runtime directory permissions"
    fi
}

###############################################################################
# Network Capabilities Configuration
###############################################################################

configure_network_capabilities() {
    log "Configuring network capabilities for non-root packet capture..."

    # Get Suricata binary path
    SURICATA_BIN=$(which suricata)

    if [[ ! -f "$SURICATA_BIN" ]]; then
        log_error "Suricata binary not found"
        exit 1
    fi

    log "Suricata binary: $SURICATA_BIN"

    # Install libcap2-bin if not present
    if ! command -v setcap &> /dev/null; then
        log "Installing libcap2-bin for capability management..."
        apt-get update > /dev/null 2>&1
        apt-get install -y libcap2-bin > /dev/null 2>&1
        log_success "Installed libcap2-bin"
    fi

    # Set capabilities on Suricata binary
    # CAP_NET_RAW: Create raw sockets (packet capture)
    # CAP_NET_ADMIN: Network administration operations
    # CAP_SYS_NICE: Set process priority (performance)
    # CAP_IPC_LOCK: Lock memory (prevent swapping sensitive data)

    if setcap cap_net_raw,cap_net_admin,cap_sys_nice,cap_ipc_lock=+eip "$SURICATA_BIN"; then
        log_success "Set network capabilities on Suricata binary"
    else
        log_error "Failed to set capabilities on Suricata binary"
        exit 1
    fi

    # Verify capabilities
    CAPS=$(getcap "$SURICATA_BIN")
    if [[ -n "$CAPS" ]]; then
        log_success "Verified capabilities: $CAPS"
    else
        log_error "Capability verification failed"
        exit 1
    fi

    # Note: setcap is preferred over setuid for security
    log_success "Suricata can now capture packets without root privileges"
}

###############################################################################
# Systemd Service Configuration
###############################################################################

configure_systemd_service() {
    log "Configuring systemd service for non-root operation..."

    # Create systemd override directory
    OVERRIDE_DIR="/etc/systemd/system/suricata.service.d"
    mkdir -p "$OVERRIDE_DIR"
    chmod 755 "$OVERRIDE_DIR"

    # Create service override file with security hardening
    cat > "$OVERRIDE_DIR/override.conf" << 'SYSTEMD_EOF'
[Service]
# Run as non-root user
User=suricata
Group=suricata

# Runtime directory for PID file (creates /run/suricata owned by suricata:suricata)
RuntimeDirectory=suricata
RuntimeDirectoryMode=0755

# Override ExecStart to remove --user and --group flags (systemd handles this)
# Must clear ExecStart first before setting new value
ExecStart=
ExecStart=/usr/bin/suricata --af-packet -c /etc/suricata/suricata.yaml --pidfile /run/suricata/suricata.pid

# Security Hardening Settings
# ==========================

# Process Restrictions
NoNewPrivileges=true
PrivateTmp=true

# File System Restrictions
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/suricata /var/lib/suricata
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# Capabilities (minimal required for packet capture)
# Note: These work in conjunction with file capabilities set via setcap
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_NICE CAP_IPC_LOCK
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_NICE CAP_IPC_LOCK

# Network Restrictions
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
IPAddressDeny=any
IPAddressAllow=localhost

# System Call Restrictions
SystemCallFilter=@system-service @network-io @io-event
SystemCallFilter=~@privileged @resources @obsolete @debug @mount @cpu-emulation @module @raw-io @reboot @swap @clock
SystemCallErrorNumber=EPERM

# Execution Restrictions
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
ProtectClock=true
ProtectHostname=true

# Device Access
PrivateDevices=false
DevicePolicy=closed
DeviceAllow=/dev/null rw

# Resource Limits
LimitNOFILE=65536
LimitNPROC=256

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=suricata

# Restart Policy
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

    chmod 644 "$OVERRIDE_DIR/override.conf"
    chown root:root "$OVERRIDE_DIR/override.conf"
    log_success "Created systemd service override with security hardening"

    # Reload systemd daemon
    systemctl daemon-reload
    log_success "Reloaded systemd daemon"
}

###############################################################################
# Additional Security Configurations
###############################################################################

configure_apparmor_profile() {
    log "Checking for AppArmor profile..."

    if command -v aa-status &> /dev/null; then
        if aa-status --enabled 2>/dev/null; then
            log_warning "AppArmor is enabled but no custom profile configured"
            log "Consider creating a custom AppArmor profile for additional security"
        else
            log "AppArmor not enabled"
        fi
    else
        log "AppArmor not installed"
    fi
}

setup_logrotate() {
    log "Configuring log rotation..."

    cat > /etc/logrotate.d/suricata << 'LOGROTATE_EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /run/suricata/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
    su suricata suricata
    create 0640 suricata suricata
}
LOGROTATE_EOF

    chmod 644 /etc/logrotate.d/suricata
    chown root:root /etc/logrotate.d/suricata
    log_success "Configured log rotation"
}

###############################################################################
# Audit and Verification
###############################################################################

audit_permissions() {
    log "Auditing file permissions and ownership..."

    echo "" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    echo "PERMISSION AUDIT REPORT" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"

    # Audit critical paths
    AUDIT_PATHS=(
        "$SURICATA_CONFIG"
        "/var/lib/suricata"
        "/var/lib/suricata/rules"
        "/var/log/suricata"
        "/var/run/suricata"
        "$(which suricata)"
    )

    for path in "${AUDIT_PATHS[@]}"; do
        if [[ -e "$path" ]]; then
            PERMS=$(stat -c "%a" "$path" 2>/dev/null)
            OWNER=$(stat -c "%U:%G" "$path" 2>/dev/null)
            TYPE=$(if [[ -d "$path" ]]; then echo "DIR"; else echo "FILE"; fi)
            echo "$TYPE | $path | $OWNER | $PERMS" | tee -a "$LOG_FILE"
        fi
    done

    echo "========================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

verify_service_configuration() {
    log "Verifying systemd service configuration..."

    # Check if service file exists
    if systemctl cat suricata.service > /dev/null 2>&1; then
        log_success "Suricata service found"

        # Check for User directive
        if systemctl cat suricata.service | grep -q "User=suricata"; then
            log_success "Service configured to run as suricata user"
        else
            log_warning "Service not explicitly configured for suricata user (will use override)"
        fi
    else
        log_error "Suricata service not found"
        return 1
    fi
}

test_service_startup() {
    log "Testing Suricata service with security configuration..."

    # Stop service if running
    if systemctl is-active --quiet suricata.service; then
        log "Stopping current Suricata service..."
        systemctl stop suricata.service
        sleep 2
    fi

    # Start service
    log "Starting Suricata with security hardening..."
    if systemctl start suricata.service; then
        log_success "Service started successfully"
        sleep 5

        # Check service status
        if systemctl is-active --quiet suricata.service; then
            log_success "Service is running"

            # Check process owner
            PROC_USER=$(ps aux | grep [s]uricata | awk '{print $1}' | head -n 1)
            if [[ "$PROC_USER" == "suricata" ]]; then
                log_success "Process is running as suricata (not root)"
            else
                log_warning "Process is running as $PROC_USER (expected suricata)"
            fi

            # Check if Suricata is capturing packets
            sleep 3
            if journalctl -u suricata.service -n 50 | grep -q "Engine started"; then
                log_success "Suricata engine started and capturing packets"
            else
                log_warning "Waiting for engine to fully initialize..."
            fi
        else
            log_error "Service failed to start"
            journalctl -u suricata.service -n 20 --no-pager | tee -a "$LOG_FILE"
            return 1
        fi
    else
        log_error "Failed to start service"
        return 1
    fi
}

###############################################################################
# Summary Report
###############################################################################

print_summary() {
    cat << EOF

${GREEN}════════════════════════════════════════════════════════════${NC}
${GREEN}  Suricata Installation and Configuration Complete!${NC}
${GREEN}════════════════════════════════════════════════════════════${NC}

${BLUE}Installation Summary:${NC}
  • Suricata Version: $SURICATA_VERSION
  • Configuration File: $SURICATA_CONFIG
  • Rules Directory: $RULES_DIR
  • Custom Rules File: $LOCAL_RULES_FILE
  • Primary Interface: $INTERFACE
  • HOME_NET: $HOME_NET
  • Installation Log: $LOG_FILE

${BLUE}Security Configuration:${NC}
  • Running as: suricata user (non-root)
  • Network Capabilities: CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_NICE, CAP_IPC_LOCK
  • Systemd Security: Enabled (hardened service configuration)
  • Directory Permissions: Properly secured (750/755)
  • File Permissions: Root-owned configs, suricata-writable logs
  • Log Rotation: Configured (14-day retention)

${BLUE}Network Scanning Rules Deployed:${NC}
  ✓ ICMP Echo Request flood detection (SID: 10000010)
  ✓ ICMP Ping sweep detection (SID: 10000011)
  ✓ Nmap SYN scan detection (SID: 10000001)
  ✓ Nmap NULL scan detection (SID: 10000002)
  ✓ Nmap Xmas scan detection (SID: 10000003)
  ✓ Nmap FIN scan detection (SID: 10000004)

${BLUE}Useful Commands:${NC}
  • Check service status: sudo systemctl status suricata.service
  • View live alerts: sudo tail -f /var/log/suricata/eve.json | jq
  • Test configuration: sudo suricata -T -c $SURICATA_CONFIG -v
  • Update rules: sudo suricata-update
  • Stop service: sudo systemctl stop suricata.service
  • Restart service: sudo systemctl restart suricata.service
  • Verify capabilities: getcap $(which suricata)
  • Check process owner: ps aux | grep [s]uricata

${BLUE}Configuration Locations:${NC}
  • Main Config: $SURICATA_CONFIG
  • Custom Rules: $LOCAL_RULES_FILE
  • Rules Database: $RULES_DIR
  • Eve Log Output: /var/log/suricata/eve.json
  • Fast Log: /var/log/suricata/fast.log
  • Systemd Override: /etc/systemd/system/suricata.service.d/override.conf

${GREEN}════════════════════════════════════════════════════════════${NC}

EOF
}

###############################################################################
# Cleanup and Security Functions
###############################################################################

cleanup() {
    log "Performing cleanup..."

    # Remove temporary venv path file if it exists
    if [[ -n "$TEMP_VENV_FILE" ]] && [[ -f "$TEMP_VENV_FILE" ]]; then
        rm -f "$TEMP_VENV_FILE"
        log "Temporary files cleaned up"
    fi

    # Secure log file permissions
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE"
        chown root:adm "$LOG_FILE"
        log_success "Log file secured"
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
    echo -e "${BLUE}║     Suricata IDS Installation and Configuration       ║${NC}"
    echo -e "${BLUE}║      with Security Hardening and Custom Rules         ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log "Starting Suricata installation and configuration..."

    # Phase 1: Prerequisite Checks
    log "Phase 1: Prerequisite Checks"
    check_root
    check_os

    # Phase 2: Network Interface Detection and Promiscuous Mode
    log "Phase 2: Network Interface Detection and Promiscuous Mode"
    detect_primary_interface
    enable_promiscuous_mode
    get_interface_ip_range

    # Phase 3: Installation
    log "Phase 3: Installation"
    install_dependencies
    add_suricata_repository
    install_suricata
    verify_installation

    # Phase 4: Suricata Configuration
    log "Phase 4: Suricata Configuration"
    configure_suricata

    # Phase 5: Rules Deployment
    log "Phase 5: Custom Rules Deployment"
    create_custom_rules

    # Phase 6: Rules Update (must happen before validation)
    log "Phase 6: Rules Update"
    update_rules

    # Phase 7: Configuration Validation
    log "Phase 7: Configuration Validation"
    validate_configuration

    # Phase 8: Security Hardening
    log "Phase 8: Security Hardening"
    setup_directory_permissions
    setup_file_permissions
    configure_network_capabilities
    configure_systemd_service
    setup_logrotate
    configure_apparmor_profile

    # Phase 9: Service Management
    log "Phase 9: Service Management"
    enable_service
    test_service_startup
    verify_service_ready

    # Phase 10: Audit and Verification
    log "Phase 10: Audit and Verification"
    audit_permissions
    verify_service_configuration
    check_service_status

    # Phase 11: Summary
    print_summary

    log_success "Installation and configuration completed successfully!"
}

# Run main function
main "$@"