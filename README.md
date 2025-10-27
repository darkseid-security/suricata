# Suricata IDS Installation and Security Hardening

This directory contains two scripts for deploying Suricata IDS with security hardening and custom detection rules.

## Scripts Overview

### 1. `setup_suricata_user.sh`
**Purpose**: Creates a dedicated system user for Suricata

**What it does**:
- Creates `suricata` system group
- Creates `suricata` system user with restricted shell (`/usr/sbin/nologin`)
- Locks the account to prevent password authentication
- Verifies user creation

**What it does NOT do**:
- Does NOT install Suricata
- Does NOT configure directories or permissions
- Does NOT set up services
- Does NOT configure network capabilities

**Run this script FIRST** before installing Suricata.

### 2. `suricata_install.sh`
**Purpose**: Installs, configures, and hardens Suricata IDS

**What it does**:
- Detects network interface and enables promiscuous mode
- Installs Suricata and dependencies
- Configures Suricata with proper HOME_NET and interface settings
- Deploys custom detection rules for network reconnaissance
- Updates Suricata rules database
- Sets up directory structure with proper permissions
- Configures network capabilities (CAP_NET_RAW, etc.)
- Creates systemd service override with security hardening
- Sets up log rotation
- Verifies service runs as non-root user
- Tests and audits the complete setup

## Installation Order

**IMPORTANT**: Run scripts in this exact order:

```bash
# Step 1: Create the suricata service user
sudo ./setup_suricata_user.sh

# Step 2: Install and configure Suricata with security hardening
sudo ./suricata_install.sh
```

## Changes Made

### `setup_suricata_user.sh` - Simplified
**Before**: 619 lines with extensive security configuration
**After**: 192 lines - ONLY creates the service user

**Removed**:
- Directory permission setup
- File permission configuration
- Network capabilities configuration
- Systemd service override creation
- Log rotation setup
- Service testing and verification
- AppArmor profile checking

**Kept**:
- User/group creation
- Account locking
- Basic logging

### `suricata_install.sh` - Enhanced
**Before**: 637 lines, missing Phase 4 (configuration)
**After**: 1030 lines with complete security hardening

**Added**:
- **Phase 4**: Suricata configuration (configure_suricata function now called)
- **Phase 8**: Security hardening
  - `setup_directory_permissions()` - Creates and secures directories
  - `setup_file_permissions()` - Secures config and rules files
  - `configure_network_capabilities()` - Sets Linux capabilities
  - `configure_systemd_service()` - Creates hardened service override
  - `setup_logrotate()` - Configures log rotation
  - `configure_apparmor_profile()` - Checks for AppArmor
- **Phase 10**: Audit and verification
  - `audit_permissions()` - Audits all file/directory permissions
  - `verify_service_configuration()` - Verifies systemd configuration
  - `test_service_startup()` - Tests service runs as suricata user

**Fixed**:
- Missing `configure_suricata()` call in main() function
- Updated summary to include security configuration details

## Security Features

### User Isolation
- Suricata runs as dedicated `suricata` user (not root)
- User has no login shell
- Account is locked (no password authentication)

### Network Capabilities
- CAP_NET_RAW: Raw socket creation (packet capture)
- CAP_NET_ADMIN: Network administration operations
- CAP_SYS_NICE: Process priority management
- CAP_IPC_LOCK: Memory locking (prevents sensitive data swapping)

### Systemd Hardening
- NoNewPrivileges=true
- PrivateTmp=true
- ProtectSystem=strict
- ProtectHome=true
- Restricted system calls
- Memory execution protection
- Namespace restrictions
- Capability bounding

### File Permissions
- Config files: `root:suricata` (640) - read-only for suricata
- Rules files: `root:suricata` (640) - read-only for suricata
- Log files: `suricata:suricata` (640) - writable by suricata
- Directories: `suricata:suricata` (750/755)

## Detection Rules

The installation includes custom rules for detecting network reconnaissance:

- ICMP Echo Request flood detection (SID: 10000010)
- ICMP Ping sweep detection (SID: 10000011)
- Nmap SYN scan detection (SID: 10000001)
- Nmap NULL scan detection (SID: 10000002)
- Nmap Xmas scan detection (SID: 10000003)
- Nmap FIN scan detection (SID: 10000004)

## Useful Commands

```bash
# Check service status
sudo systemctl status suricata.service

# View live alerts
sudo tail -f /var/log/suricata/eve.json | jq

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Update rules
sudo suricata-update

# Verify capabilities
getcap $(which suricata)

# Check process owner
ps aux | grep [s]uricata

# View logs
sudo journalctl -u suricata.service -f
```

## Log Files

- Installation log: `/var/log/suricata_install.log`
- User setup log: `/var/log/suricata_user_setup.log`
- Suricata logs: `/var/log/suricata/`

## Troubleshooting

### Service won't start
```bash
# Check service logs
sudo journalctl -u suricata.service -n 50

# Verify configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Check permissions
ls -la /var/log/suricata
ls -la /var/lib/suricata
```

### Common Errors

**"capng_change_id for main thread failed"**
- This means the service is trying to drop privileges when already running as non-root
- Fixed by removing `--user` and `--group` flags from ExecStart (systemd handles this)

**"unable to set pidfile '/run/suricata.pid': Permission denied"**
- PID file location not writable by suricata user
- Fixed by using `RuntimeDirectory=suricata` and PID file at `/run/suricata/suricata.pid`

**"Failed to change ownership of file /var/log/suricata//suricata.log"**
- Note the double slash - this is a warning, not a critical error
- Log files are created with correct permissions

### Permission denied errors
```bash
# Verify user exists
id suricata

# Check capabilities
getcap $(which suricata)

# Verify directory ownership
sudo ls -la /var/lib/suricata /var/log/suricata

# Check runtime directory
ls -la /run/suricata/

# Verify systemd override is applied
systemctl cat suricata.service | grep -A 5 "override.conf"
```

### After reinstalling or updating Suricata
If you reinstall or update Suricata, you may need to:
```bash
# Reapply network capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice,cap_ipc_lock=+eip $(which suricata)

# Reload systemd configuration
sudo systemctl daemon-reload

# Restart service
sudo systemctl restart suricata.service
```

## Requirements

- Debian/Ubuntu Linux
- Root/sudo access
- Network interface in promiscuous mode support
- Python 3 (for configuration management)

## License

These scripts are for authorized security testing and defensive security purposes only.
