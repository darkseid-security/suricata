# Suricata IDS Automated Installation & Configuration

A comprehensive Bash script for automated installation, configuration, and deployment of Suricata IDS (Intrusion Detection System) with custom detection rules for network reconnaissance scanning.

## Features

- **Automated Installation**: One-command setup of Suricata IDS on Debian/Ubuntu systems
- **Custom Detection Rules**: Pre-configured rules for detecting common network reconnaissance activities
- **Network Auto-Discovery**: Automatically detects primary network interface and calculates network ranges
- **Python YAML Configuration**: Uses PyYAML for robust configuration file manipulation
- **Comprehensive Logging**: Detailed installation and configuration logs
- **Service Management**: Automatic service enablement and startup verification

## Detection Capabilities

The script deploys custom Suricata rules to detect:

- **ICMP Echo Request Flood** (SID: 10000010) - Detects ping floods and sweep attempts
- **ICMP Ping Sweep** (SID: 10000011) - Identifies scanning across multiple destinations
- **Nmap SYN Scan** (SID: 10000001) - Detects TCP SYN stealth scans
- **Nmap NULL Scan** (SID: 10000002) - Identifies packets with no TCP flags
- **Nmap Xmas Scan** (SID: 10000003) - Detects FIN+PSH+URG flag combinations
- **Nmap FIN Scan** (SID: 10000004) - Identifies FIN-only TCP packets

## Prerequisites

- Debian or Ubuntu Linux distribution
- Root/sudo privileges
- Internet connectivity for package downloads
- Python 3.x (installed automatically)

## Installation

### Quick Start

```bash
# Clone or download the script
git clone <repository-url>
cd Threat_Detection

# Make the script executable
chmod +x suricata.sh

# Run with root privileges
sudo ./suricata.sh
```

## What the Script Does

### Phase 1: Prerequisite Checks
- Verifies root privileges
- Confirms Debian/Ubuntu operating system

### Phase 2: Installation
- Installs required dependencies (Python 3, pip, venv)
- Creates Python virtual environment for package isolation
- Adds Suricata stable PPA repository
- Installs Suricata IDS and jq (JSON processor)

### Phase 3: Network Configuration
- Auto-detects primary network interface
- Retrieves IP address and calculates network range (CIDR)
- Configures HOME_NET variable

### Phase 4: Suricata Configuration
- Restores clean configuration from package
- Creates timestamped backup of configuration
- Uses PyYAML to safely modify YAML configuration:
  - Sets HOME_NET to detected network range
  - Configures rule paths and files
  - Sets up pcap and af-packet interfaces
  - Maintains YAML 1.1 compliance

### Phase 5: Custom Rules Deployment
- Creates custom detection rules in `/var/lib/suricata/rules/local.rules`
- Deploys reconnaissance and scanning detection signatures

### Phase 6: Rules Update
- Runs `suricata-update` to fetch latest rule sets
- Restarts service to apply new rules

### Phase 7: Configuration Validation
- Validates Suricata configuration syntax
- Verifies rule loading

### Phase 8: Service Management
- Enables Suricata service for auto-start
- Starts Suricata service
- Verifies full initialization with rule loading
- Displays service status

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/suricata/suricata.yaml` | Main Suricata configuration |
| `/var/lib/suricata/rules/local.rules` | Custom detection rules |
| `/var/lib/suricata/rules/` | Rules database directory |
| `/var/log/suricata/eve.json` | JSON event log output |
| `/var/log/suricata/fast.log` | Fast alert format log |
| `/var/log/suricata_install.log` | Installation script log |

## Useful Commands

### Service Management
```bash
# Check service status
sudo systemctl status suricata.service

# Restart service
sudo systemctl restart suricata.service

# Stop service
sudo systemctl stop suricata.service
```

### Monitoring Alerts
```bash
# View live alerts (formatted JSON)
sudo tail -f /var/log/suricata/eve.json | jq

# View fast log alerts
sudo tail -f /var/log/suricata/fast.log

# View recent alerts with jq filtering
sudo jq 'select(.event_type=="alert")' /var/log/suricata/eve.json | tail -n 20
```

### Configuration Management
```bash
# Test configuration validity
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Update rule sets
sudo suricata-update

# List loaded rules
sudo suricata-update list-sources
```

## Log Analysis

The script creates detailed logs at `/var/log/suricata_install.log` containing:
- Timestamped installation steps
- Success/error/warning messages
- Configuration changes
- Service status information

## Troubleshooting

### Service Won't Start
```bash
# Check detailed service status
sudo systemctl status suricata.service -l

# View recent logs
sudo journalctl -u suricata.service -n 50

# Validate configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

### Rules Not Loading
```bash
# Update rules manually
sudo suricata-update

# Restart service
sudo systemctl restart suricata.service

# Check rules directory
ls -la /var/lib/suricata/rules/
```

### Interface Detection Issues
The script auto-detects the primary interface. If this fails:
1. Check `ip route` output
2. Manually edit `/etc/suricata/suricata.yaml`
3. Set `af-packet` interface to your network interface

## Security Considerations

- **Root Privileges Required**: The script must run as root to install packages and configure system services
- **Network Monitoring**: Suricata will monitor all traffic on the configured interface
- **Performance Impact**: IDS monitoring may impact network performance on high-traffic systems
- **Python Virtual Environment**: Dependencies are isolated in a venv to prevent system conflicts

## Custom Rule Development

To add custom rules, edit `/var/lib/suricata/rules/local.rules`:

```bash
sudo nano /var/lib/suricata/rules/local.rules
```

Rule syntax example:
```
alert tcp any any -> $HOME_NET any (msg:"Custom Alert"; flags:S; sid:10000100; rev:1;)
```

After editing rules:
```bash
sudo systemctl restart suricata.service
```

## Architecture

- **Language**: Bash
- **Configuration Management**: Python 3 with PyYAML
- **Package Manager**: APT (Debian/Ubuntu)
- **Service Manager**: systemd
- **Log Format**: JSON (EVE format)

## Contributing

Contributions are welcome! Areas for enhancement:
- Support for additional Linux distributions
- More detection rule signatures
- Integration with SIEM systems
- Performance tuning options
- Multi-interface support

## License

This script is provided as-is for educational and defensive security purposes.

## Disclaimer

This tool is intended for authorized security monitoring and defensive purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when deploying network monitoring systems.

## Support

For issues or questions:
1. Check the installation log at `/var/log/suricata_install.log`
2. Review Suricata documentation at https://suricata.io/docs/
3. Verify system requirements and compatibility

## Version

- **Script Version**: 1.0
- **Supported Suricata Versions**: 6.x and 7.x
- **Supported OS**: Debian 10+, Ubuntu 20.04+

---

**Note**: Always test in a non-production environment before deploying to production systems.
