# Aura-sec v0.5.1
# A unique and easy-to-use scanner for the community.
# Coded by Irfan-sec
# GitHub: https://github.com/irfan-sec

import socket
import sys
import threading
from queue import Queue

# --- Global variables for threads to access ---
target_ip = ""
port_queue = Queue()
print_lock = threading.Lock() # Our new "talking stick" for printing

# --- Functions ---

def main_menu():
    # This function stays the same
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan (Coming Soon!)")
    choice = input("Enter your choice (1 or 2): ")
    return choice

def get_target():
    # This function stays the same
    target = input("Please enter the target IP address: ")
    return target

def get_ports():
    # This function stays the same
    while True:
        choice = input("Select port range:\n1. Common Ports (1-1024)\n2. Custom Range\nEnter choice (1 or 2): ")
        if choice == '1':
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

def scan_port(port):
    """Scans a single port and grabs the service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        if s.connect_ex((target_ip, port)) == 0:
            try:
                banner = s.recv(1024).decode('utf-8').strip()
                with print_lock: # Ask for the "talking stick" before printing
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m  |  \033[96mVersion Info: {banner}\033[0m")
            except:
                with print_lock: # Ask for the "talking stick" before printing
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m")
        
        s.close()
    except socket.error:
        pass

def worker():
    """The job for each thread. It takes a port from the queue and scans it."""
    # This function stays the same
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(port)
        port_queue.task_done()

# --- Main Program ---

# This section stays the same as v0.5
banner = r"""
  
   _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/ 
 
"""
print(banner)
print("          Welcome to Aura-sec v0.5.1")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)

scan_choice = main_menu()

if scan_choice == '1':
    # This section also stays the same as v0.5
    target_ip = get_target()
    port_range = get_ports()

    for port in port_range:
        port_queue.put(port)
    
    num_threads = 100
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    port_queue.join()

    for thread in threads:
        thread.join()

    print("-" * 50)
    print("[*] Scan complete.")

elif scan_choice == '2':
    # This section stays the same
    print("\n[!] The Anonymous Scan feature is coming in a future version!")
    print("    We will build this in Phase 2 using a proxy like Tor.")
else:
    # This section stays the same
    print("\n[!] Invalid choice. Please run the program again and select 1 or 2.")

print("\nThank you for using Aura-sec!")