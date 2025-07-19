# Tailscale SSH Connector

A Python utility for easily connecting to Tailscale machines via SSH with credential management.

Reworked with Claude for better usability.

## Overview

This tool automatically discovers online Tailscale machines, checks for SSH connectivity, and provides an interactive interface for connecting with saved credentials.

## Features

- 🔍 Auto-discovery of online Tailscale machines
- 🚀 Parallel SSH port scanning for quick results
- 🔐 Secure credential storage using system keyring
- 🔑 Support for both SSH key and password authentication
- 💾 Remember authentication preferences per machine/user
- 🖥️ Cross-platform compatibility
- ⚡ Fast, concurrent connectivity checks

## System Compatibility

### Supported Operating Systems
- ✅ **Linux** (fully supported)
- ✅ **macOS** (fully supported) (Untested)
- ⚠️ **Windows** (requires WSL or Git Bash) (Untested)

### Required Dependencies

#### System Dependencies
- **Tailscale** - Must be installed and configured
- **OpenSSH client** (`ssh`) - Usually pre-installed on Unix systems
- **sshpass** (optional) - Only required for password-based authentication

#### Python Dependencies
- **Python 3.6+**
- **keyring** library for credential storage

## Installation

### Manual Installation

#### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip sshpass openssh-client
```

**CentOS/RHEL/Fedora:**
```bash
# RHEL/CentOS
sudo yum install python3 python3-pip sshpass openssh-clients

# Fedora
sudo dnf install python3 python3-pip sshpass openssh-clients
```

**macOS:**
```bash
# Using Homebrew
brew install python sshpass

# Python should include pip
```

**Windows (WSL):**
```bash
# First install WSL, then use Ubuntu commands above
sudo apt update
sudo apt install python3 python3-pip sshpass openssh-client
```

#### 2. Install Tailscale
Follow instructions at: https://tailscale.com/download

#### 3. Install Python Dependencies
```bash
pip3 install --user keyring
```

#### 4. Download and Setup Script
```bash
# Download the script
wget https://raw.githubusercontent.com/ParadoxLeon/tailssh/main/tailsshport.py
# OR
curl -O https://raw.githubusercontent.com/ParadoxLeon/tailssh/main/tailsshport.py

# Make executable
chmod +x tailsshport.py
```

## Usage

### Basic Usage
```bash
python3 tailsshport.py
```
### Alias
Place this into you're `.bashrc` then `source .bashrc` and execute with `tailssh`
```bash
alias tailssh="python3 ~/tailsshport.py"
```


### Command Line Options
```bash
python3 tailsshport.py --help
python3 tailsshport.py --list-only    # Just list machines and exit
python3 tailsshport.py --debug        # Enable debug logging

# With Alias
tailssh --help
tailssh --list-only    # Just list machines and exit
tailssh --debug        # Enable debug logging
```

### Interactive Flow
```
Getting Tailscale status... Done!
Checking SSH connectivity for 5 machines.....
Found 3 machines with SSH available.

Index Name                      IP             OS        Status
======================================================================
0     server1.tail-net.ts.net  100.64.0.2     linux     online
1     workstation.tail-net      100.64.0.5     darwin    online
2     pi.tail-net              100.64.0.8     linux     online

Enter the index of the machine to connect to (0-2), or 'r' to refresh: 0
Enter SSH username for server1.tail-net.ts.net (default: root): admin
Use SSH key authentication? (y/N): y
Path to SSH key (default: ~/.ssh/id_rsa):
Save this SSH key path for future use? (y/N): y
Connecting to server1.tail-net.ts.net (100.64.0.2) as admin...
```

## Configuration

### Keyring Backend
The script uses your system's keyring for secure credential storage:

- **Linux**: Automatically detects (KWallet, GNOME Keyring, etc.)
- **macOS**: Uses Keychain
- **Windows**: Uses Windows Credential Store

You can override the keyring backend by setting:
```bash
export PYTHON_KEYRING_BACKEND="keyring.backends.SecretService.Keyring"
```

### SSH Key Management
- Default SSH key location: `~/.ssh/id_rsa`
- Supports custom key paths
- Automatically fixes key permissions (600)
- Per-machine/user key preferences saved

## Troubleshooting

### Common Issues

#### "Tailscale is not installed or not in PATH"
```bash
# Check if Tailscale is installed
which tailscale
# If not found, install from: https://tailscale.com/download
```

#### "sshpass is required but not installed"
```bash
# Ubuntu/Debian
sudo apt install sshpass

# CentOS/RHEL
sudo yum install sshpass

# macOS
brew install sshpass
```

#### "Keyring error"
The script will continue working but won't save credentials. To fix:
```bash
# Linux - install keyring backend
sudo apt install python3-keyring

# macOS - should work out of box
# Windows - install keyring backend
```

#### Permission Denied (SSH Key)
```bash
# Fix SSH key permissions
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh
```

#### No machines found
```bash
# Check Tailscale status
tailscale status

# Ensure machines are online and reachable
# Check if SSH is running on target machines:
# sudo systemctl enable ssh
# sudo systemctl start ssh
```

### Debug Mode
Run with `--debug` for detailed logging:
```bash
python3 tailsshport.py --debug
```

## Security Notes

- Credentials are stored in your system's secure keyring
- SSH connections use standard OpenSSH security
- Supports SSH key authentication (recommended)
- Disables host key checking for Tailscale networks (acceptable risk)
- No credentials are stored in plain text

## Platform-Specific Notes

### Linux
- Fully supported on all major distributions
- Requires D-Bus for keyring functionality
- KWallet backend preferred on KDE systems

### macOS (Untested)
- Fully supported with Homebrew dependencies
- Uses system Keychain for credential storage
- May require Xcode command line tools

### Windows (Untested)
- Requires WSL (Windows Subsystem for Linux)
- Or use Git Bash with Python
- Windows Credential Store used for keyring


### Universal Compatibility Assessment

**✅ Mostly Universal** - The script can run on multiple systems with minor setup:

**Strengths:**
- Uses Python standard library extensively
- Graceful fallbacks for missing features
- Cross-platform file path handling with `os.path`
- Subprocess usage instead of shell-specific commands

**Areas for Improvement:**
- Hardcoded KWallet keyring backend (Linux KDE specific)
- Unix-specific file permissions handling
- Assumes Unix-style SSH key paths

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test across platforms
4. Submit a pull request

## License

MIT License - feel free to modify and distribute.

## Support

- Create issues for bugs or feature requests
- Check Tailscale documentation for network issues
- Verify SSH service is running on target machines
