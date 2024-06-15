#!/usr/bin/env python3

import subprocess
import re
import os

def get_tailscale_status():
    result = subprocess.run(['tailscale', 'status'], stdout=subprocess.PIPE, text=True)
    return result.stdout

def parse_status_output(output):
    machines = []
    for line in output.splitlines():
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)', line)
        if match and match.group(4) != 'offline':
            machines.append({
                'ip': match.group(1),
                'name': match.group(2),
                'os': match.group(3),
                'status': match.group(4)
            })
    return machines

def display_machines(machines):
    print(f"{'Index':<5} {'Name':<25} {'IP':<15} {'OS':<10}")
    print("=" * 60)
    for idx, machine in enumerate(machines):
        print(f"{idx:<5} {machine['name']:<25} {machine['ip']:<15} {machine['os']:<10}")

def main():
    # Get Tailscale status
    status_output = get_tailscale_status()
    machines = parse_status_output(status_output)

    if not machines:
        print("No online machines found.")
        return

    # Display the list of machines
    display_machines(machines)

    # Ask the user to select a machine
    while True:
        try:
            selection = int(input("\nEnter the index of the machine to connect to: "))
            if 0 <= selection < len(machines):
                selected_machine = machines[selection]
                break
            else:
                print("Invalid selection. Please enter a valid index.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Ask the user for the SSH username
    username = input("Enter SSH username (default: root): ").strip() or "root"

    # Establish SSH connection to the selected machine
    os.system(f"ssh {username}@{selected_machine['ip']}")

if __name__ == '__main__':
    main()
