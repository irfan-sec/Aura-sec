# Aura-sec v0.3
# A unique and easy-to-use scanner for the community.
# Coded by Irfan Ali with guidance from an AI mentor.

import socket
import sys

# --- Functions ---

def main_menu():
    """Displays the main menu and gets the user's choice."""
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan (Coming Soon!)")
    choice = input("Enter your choice (1 or 2): ")
    return choice

def get_target():
    """Gets the target IP address from the user."""
    target = input("Please enter the target IP address: ")
    return target

def get_ports():
    """Gets the port scanning option and range from the user."""
    while True:
        choice = input("Select port range:\n1. Common Ports (1-1024)\n2. Custom Range\nEnter choice (1 or 2): ")
        if choice == '1':
            # We'll scan the first 1024 ports, which are the most common
            return range(1, 1025)
        elif choice == '2':
            try:
                start_port = int(input("Enter start port: "))
                end_port = int(input("Enter end port: "))
                return range(start_port, end_port + 1)
            except ValueError:
                print("[!] Invalid input. Please enter numbers only.")
        else:
            print("[!] Invalid choice. Please enter 1 or 2.")

def scan_port(ip, port):
    """Scans a single port on the target IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            print(f"\033[92m[+] Port {port} is OPEN\033[0m")
        s.close()
    except socket.error:
        pass

# --- Main Program ---

# Display a nice banner for our tool
print("-" * 50)
print("        Welcome to Aura-sec v0.3")
print("      A scanner built for the community")
print("-" * 50)

# Get the user's main choice
scan_choice = main_menu()

# --- Main Logic ---
if scan_choice == '1':
    # --- Normal Scan Logic ---
    target_ip = get_target()
    port_range = get_ports()

    print(f"\n[*] Starting Normal Scan on target: {target_ip}")
    print("-" * 50)
    try:
        for port in port_range:
            scan_port(target_ip, port)
    except KeyboardInterrupt:
        print("\n[!] Exiting program.")
        sys.exit()
    
    print("-" * 50)
    print("[*] Scan complete.")

elif scan_choice == '2':
    # --- Placeholder for our future Anonymous Scan feature ---
    print("\n[!] The Anonymous Scan feature is coming in a future version!")
    print("    We will build this in Phase 2 using a proxy like Tor.")

else:
    print("\n[!] Invalid choice. Please run the program again and select 1 or 2.")


print("\nThank you for using Aura-sec v0.3!")
print("Stay tuned for more features and updates.")