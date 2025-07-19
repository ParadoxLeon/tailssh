#!/usr/bin/env python3
import argparse
import subprocess
import re
import os
import getpass
import keyring
import socket
import keyring.errors
import logging
import sys
import shlex
import platform
from shutil import which
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVICE_NAME = 'tailscale_ssh'

def get_default_ssh_key():
    """Get default SSH key path based on platform."""
    base_path = os.path.expanduser("~/.ssh/id_rsa")

    # On Windows, also check common Git Bash locations
    if platform.system() == "Windows":
        alt_paths = [
            os.path.expanduser("~/ssh/id_rsa"),
            os.path.expanduser("~/.ssh/id_ed25519"),
        ]
        for path in [base_path] + alt_paths:
            if os.path.exists(path):
                return path

    return base_path

DEFAULT_SSH_KEY = get_default_ssh_key()

def setup_keyring_backend():
    """Setup keyring backend based on platform."""
    system = platform.system()

    if system == "Darwin":  # macOS
        os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.macOS.Keyring")
    elif system == "Windows":
        os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.Windows.WinVaultKeyring")
    elif system == "Linux":
        # Try to detect desktop environment
        desktop = os.environ.get('XDG_CURRENT_DESKTOP', '').lower()
        if 'kde' in desktop or 'plasma' in desktop:
            os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.kwallet.DBusKeyring")
        elif 'gnome' in desktop or 'unity' in desktop:
            os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.SecretService.Keyring")
        # Otherwise let keyring auto-detect

# Setup keyring backend
setup_keyring_backend()

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def safe_get_password(service, key):
    try:
        return keyring.get_password(service, key)
    except keyring.errors.KeyringError as e:
        logging.warning(f"Keyring error on get: {e}")
        return None


def safe_set_password(service, key, value):
    try:
        keyring.set_password(service, key, value)
    except keyring.errors.KeyringError as e:
        logging.warning(f"Keyring error on set: {e}")


def get_tailscale_status():
    if not which("tailscale"):
        logging.error("Tailscale is not installed or not in PATH.")
        sys.exit(1)
    try:
        result = subprocess.run(['tailscale', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, check=True, timeout=10)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get Tailscale status: {e}")
        if e.stderr:
            logging.error(f"Error output: {e.stderr}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logging.error("Tailscale status command timed out")
        sys.exit(1)


def is_ssh_port_open(ip, timeout=0.5):
    try:
        with socket.create_connection((ip, 22), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def check_machine_ssh(machine_data):
    """Check SSH connectivity for a single machine."""
    ip, name, os_name, status = machine_data
    if is_ssh_port_open(ip):
        return {
            'ip': ip,
            'name': name,
            'os': os_name,
            'status': status
        }
    return None


def parse_status_output(output):
    machines = []
    potential_machines = []
    lines = output.strip().splitlines()

    # First pass: parse all machines quickly without SSH checks
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # More flexible regex to handle different tailscale status formats
        # Matches: IP, hostname, optional machine name, OS, status
        patterns = [
            r'^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\S*\s+(\S+)\s+(\S+)',  # Current format
            r'^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\S+)',        # Alternative format
        ]

        matched = False
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                if len(groups) >= 4:
                    ip, name, os_name, status = groups[0], groups[1], groups[-2], groups[-1]
                else:
                    ip, name, status = groups[0], groups[1], groups[-1]
                    os_name = "unknown"

                # Skip offline machines and current machine
                if status.lower() in ['offline', 'idle'] or ip == '100.64.0.1':
                    continue

                potential_machines.append((ip, name, os_name, status))
                matched = True
                break

        if not matched and re.match(r'^\d+\.\d+\.\d+\.\d+', line):
            logging.debug(f"Could not parse line: {line}")

    # Second pass: check SSH connectivity in parallel
    if potential_machines:
        print(f"Checking SSH connectivity for {len(potential_machines)} machines...", end="", flush=True)
        checked_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_machine = {executor.submit(check_machine_ssh, machine): machine
                               for machine in potential_machines}

            for future in as_completed(future_to_machine):
                checked_count += 1
                print(".", end="", flush=True)
                result = future.result()
                if result:
                    machines.append(result)

        print(f"\nFound {len(machines)} machines with SSH available.")

    return machines


def display_machines(machines):
    if not machines:
        print("No online Tailscale machines with open SSH ports found.")
        return

    print(f"{'Index':<5} {'Name':<25} {'IP':<15} {'OS':<10} {'Status':<10}")
    print("=" * 70)
    for idx, m in enumerate(machines):
        print(f"{idx:<5} {m['name']:<25} {m['ip']:<15} {m['os']:<10} {m['status']:<10}")


def get_auth_preference(machine_name, username):
    return safe_get_password(SERVICE_NAME, f"{machine_name}_{username}_auth")


def save_auth_preference(machine_name, username, method):
    safe_set_password(SERVICE_NAME, f"{machine_name}_{username}_auth", method)


def get_saved_ssh_key(machine_name, username):
    return safe_get_password(SERVICE_NAME, f"{machine_name}_{username}_sshkey")


def save_ssh_key(machine_name, username, key_path):
    safe_set_password(SERVICE_NAME, f"{machine_name}_{username}_sshkey", key_path)


def validate_ssh_key(key_path):
    """Validate SSH key file exists and has proper permissions."""
    if not os.path.exists(key_path):
        return False, f"SSH key file does not exist: {key_path}"

    # Check if it's readable
    if not os.access(key_path, os.R_OK):
        return False, f"SSH key file is not readable: {key_path}"

    # Check permissions (Unix-like systems only)
    if platform.system() != "Windows":
        stat_info = os.stat(key_path)
        mode = stat_info.st_mode & 0o777
        if mode & 0o077:  # Check if group/others have any permissions
            logging.warning(f"SSH key has overly permissive permissions: {oct(mode)}")
            try:
                os.chmod(key_path, 0o600)
                logging.info(f"Fixed SSH key permissions to 600")
            except OSError as e:
                logging.warning(f"Could not fix SSH key permissions: {e}")
    else:
        logging.debug("Skipping permission check on Windows")

    return True, "Valid SSH key"


def choose_machine(machines):
    while True:
        try:
            choice = input(f"Enter the index of the machine to connect to (0-{len(machines)-1}), or 'r' to refresh: ").strip()
            if choice.lower() == 'r':
                return None  # Signal to refresh

            selection = int(choice)
            if 0 <= selection < len(machines):
                return machines[selection]
            else:
                print(f"Invalid index. Please enter a number between 0 and {len(machines)-1}.")
        except ValueError:
            print("Please enter a valid number or 'r' to refresh.")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)


def connect_to_machine(machine):
    machine_name = machine['name']
    ip = machine['ip']

    # Sanitize machine name for keyring storage
    safe_machine_name = re.sub(r'[^\w\-_.]', '_', machine_name)

    try:
        username = input(f"Enter SSH username for {machine_name} (default: root): ").strip() or "root"
    except KeyboardInterrupt:
        print("\nAborted.")
        return

    saved_auth = get_auth_preference(safe_machine_name, username)
    if saved_auth:
        use_key = saved_auth == 'key'
        print(f"Using saved authentication method: {'SSH key' if use_key else 'password'}")
    else:
        try:
            use_key = input("Use SSH key authentication? (y/N): ").strip().lower() == 'y'
            save_auth_preference(safe_machine_name, username, 'key' if use_key else 'password')
        except KeyboardInterrupt:
            print("\nAborted.")
            return

    if use_key:
        saved_key = get_saved_ssh_key(safe_machine_name, username)
        if saved_key:
            key_path = saved_key
            print(f"Using saved SSH key: {key_path}")
        else:
            try:
                key_path = input(f"Path to SSH key (default: {DEFAULT_SSH_KEY}): ").strip() or DEFAULT_SSH_KEY
            except KeyboardInterrupt:
                print("\nAborted.")
                return

        # Expand user path
        key_path = os.path.expanduser(key_path)

        valid, message = validate_ssh_key(key_path)
        if not valid:
            logging.error(message)
            return

        if not saved_key:
            try:
                save_key = input("Save this SSH key path for future use? (y/N): ").strip().lower()
                if save_key == 'y':
                    save_ssh_key(safe_machine_name, username, key_path)
            except KeyboardInterrupt:
                print("\nAborted.")
                return

        # Use subprocess.run instead of os.system for better security
        ssh_cmd = [
            'ssh',
            '-i', key_path,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10',
            f'{username}@{ip}'
        ]

    else:
        password = safe_get_password(SERVICE_NAME, f"{safe_machine_name}_{username}")
        if not password:
            try:
                password = getpass.getpass(f"Enter SSH password for {username}@{machine_name}: ")
                if not password:
                    logging.error("Password cannot be empty")
                    return

                confirm = input("Save this password for future use? (y/N): ").strip().lower()
                if confirm == 'y':
                    safe_set_password(SERVICE_NAME, f"{safe_machine_name}_{username}", password)
            except KeyboardInterrupt:
                print("\nAborted.")
                return

        if not which("sshpass"):
            system = platform.system()
            logging.error("sshpass is required for password-based auth but not installed.")
            if system == "Linux":
                logging.info("Install it with: sudo apt install sshpass (Ubuntu/Debian) or sudo dnf install sshpass (Fedora)")
            elif system == "Darwin":
                logging.info("Install it with: brew install sshpass")
            elif system == "Windows":
                logging.info("sshpass not available on Windows - use SSH key authentication instead")
            return

        # Use sshpass with subprocess for better security
        ssh_cmd = [
            'sshpass', '-p', password,
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'ConnectTimeout=10',
            f'{username}@{ip}'
        ]

    print(f"Connecting to {machine_name} ({ip}) as {username}...")
    try:
        # Use subprocess.run instead of os.system for better security and error handling
        result = subprocess.run(ssh_cmd, check=False)
        if result.returncode != 0:
            logging.warning(f"SSH connection ended with return code: {result.returncode}")
    except FileNotFoundError as e:
        logging.error(f"Command not found: {e}")
    except Exception as e:
        logging.error(f"Failed to execute SSH command: {e}")


def check_system_dependencies():
    """Check for required system dependencies."""
    missing = []
    warnings = []

    if not which("tailscale"):
        missing.append("tailscale")

    if not which("ssh"):
        missing.append("ssh")

    if not which("sshpass"):
        warnings.append("sshpass (optional - needed for password auth)")

    return missing, warnings

def main():
    parser = argparse.ArgumentParser(description="Tailscale SSH Connector with keyring support.")
    parser.add_argument('--list-only', action='store_true', help="Just list online machines and exit.")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging.")
    parser.add_argument('--check-deps', action='store_true', help="Check system dependencies and exit.")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check dependencies if requested
    if args.check_deps:
        missing, warnings = check_system_dependencies()
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Python: {platform.python_version()}")
        print(f"Keyring backend: {keyring.get_keyring().__class__.__name__}")

        if missing:
            print(f"\nMissing required dependencies: {', '.join(missing)}")
            return 1
        else:
            print("\nAll required dependencies found!")

        if warnings:
            print(f"Optional dependencies: {', '.join(warnings)}")

        return 0

    print(f"Platform: {platform.system()}")
    print(f"Using keyring backend: {keyring.get_keyring().__class__.__name__}")

    # Quick dependency check
    missing, _ = check_system_dependencies()
    if missing:
        logging.error(f"Missing required dependencies: {', '.join(missing)}")
        logging.info("Run with --check-deps for detailed dependency information")
        return 1

    while True:
        try:
            print("Getting Tailscale status...", end="", flush=True)
            status = get_tailscale_status()
            print(" Done!")

            machines = parse_status_output(status)

            if not machines:
                print("No online Tailscale machines with open SSH ports found.")
                if not args.list_only:
                    try:
                        retry = input("Press Enter to retry or Ctrl+C to exit...")
                        continue
                    except KeyboardInterrupt:
                        print("\nAborted.")
                        break
                else:
                    break

            display_machines(machines)

            if args.list_only:
                break

            selected = choose_machine(machines)
            if selected is None:  # Refresh requested
                print("\nRefreshing machine list...")
                continue

            connect_to_machine(selected)

            try:
                again = input("\nConnect to another machine? (y/N): ").strip().lower()
                if again != 'y':
                    break
            except KeyboardInterrupt:
                print("\nAborted.")
                break

        except KeyboardInterrupt:
            print("\nAborted.")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            if args.debug:
                raise
            break


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        print("\nAborted.")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
