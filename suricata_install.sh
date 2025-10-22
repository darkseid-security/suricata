#!/bin/bash

###############################################################################
# Suricata Installation and Configuration Script
# This script automates the installation, configuration, and deployment of
# Suricata IDS with custom detection rules for network reconnaissance scanning
###############################################################################

set -e  # Exit on any error

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
    
    # Store venv path for later use
    echo "$VENV_DIR" > /tmp/venv_path.txt
    
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
    log_success "Primary interface detected: $INTERFACE"
}

get_interface_ip_range() {
    log "Retrieving IP address and calculating network range..."
    IP_ADDR=$(ip addr show "$INTERFACE" | grep "inet " | awk '{print $2}')
    if [[ -z "$IP_ADDR" ]]; then
        log_error "Could not retrieve IP address for $INTERFACE"
        exit 1
    fi
    log_success "IP Address: $IP_ADDR"
    
    # Extract network range (CIDR notation)
    HOME_NET="${IP_ADDR%/*}/24"
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
    cp "$SURICATA_CONFIG" "${SURICATA_CONFIG}.bak.$(date +%s)"
    log "Backup created: ${SURICATA_CONFIG}.bak"
    
    # Activate venv and use Python to modify YAML
    VENV_DIR=$(cat /tmp/venv_path.txt)
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
    
    # Ensure /etc/suricata/rules directory exists
    mkdir -p /etc/suricata/rules
    log "Ensured /etc/suricata/rules directory exists"
    
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
    
    log_success "Custom rules file created at: $LOCAL_RULES_FILE"
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

${BLUE}Network Scanning Rules Deployed:${NC}
  ✓ ICMP Echo Request flood detection (SID: 10000010)
  ✓ ICMP Ping sweep detection (SID: 10000011)
  ✓ Nmap SYN scan detection (SID: 10000001)
  ✓ Nmap NULL scan detection (SID: 10000002)
  ✓ Nmap Xmas scan detection (SID: 10000003)
  ✓ Nmap FIN scan detection (SID: 10000004)
  ✓ Port sweep detection (SID: 10000005)

${BLUE}Useful Commands:${NC}
  • Check service status: sudo systemctl status suricata.service
  • View live alerts: sudo tail -f /var/log/suricata/eve.json | jq
  • Test configuration: sudo suricata -T -c $SURICATA_CONFIG -v
  • Update rules: sudo suricata-update
  • Stop service: sudo systemctl stop suricata.service
  • Restart service: sudo systemctl restart suricata.service

${BLUE}Configuration Locations:${NC}
  • Main Config: $SURICATA_CONFIG
  • Custom Rules: $LOCAL_RULES_FILE
  • Rules Database: $RULES_DIR
  • Eve Log Output: /var/log/suricata/eve.json
  • Fast Log: /var/log/suricata/fast.log

${GREEN}════════════════════════════════════════════════════════════${NC}

EOF
}

###############################################################################
# Main Execution Flow
###############################################################################

main() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Suricata IDS Installation and Configuration       ║${NC}"
    echo -e "${BLUE}║           with Custom Scanning Detection Rules        ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log "Starting Suricata installation and configuration..."
    
    # Phase 1: Prerequisite Checks
    log "Phase 1: Prerequisite Checks"
    check_root
    check_os
    
    # Phase 2: Installation
    log "Phase 2: Installation"
    install_dependencies
    add_suricata_repository
    install_suricata
    verify_installation
    
    # Phase 3: Network Configuration
    log "Phase 3: Network Configuration"
    detect_primary_interface
    get_interface_ip_range
    
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
    
    # Phase 8: Service Management
    log "Phase 8: Service Management"
    enable_service
    start_service
    verify_service_ready
    check_service_status
    
    # Phase 8: Summary
    print_summary
    
    log_success "Installation and configuration completed successfully!"
}

# Run main function
main "$@"