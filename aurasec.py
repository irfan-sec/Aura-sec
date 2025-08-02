"""
Aura-sec v0.5.2
A unique and easy-to-use scanner for the community.
Coded by I R F A N
GitHub: https://github.com/irfan-sec
"""
import socket
import threading
from queue import Queue

# --- Global variables for threads to access (in UPPER_CASE) ---
TARGET_IP = ""
PORT_QUEUE = Queue()
PRINT_LOCK = threading.Lock()

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
            return range(1, 1025)
        if choice == '2':
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        if sock.connect_ex((TARGET_IP, port)) == 0:
            try:
                banner = sock.recv(1024).decode('utf-8').strip()
                with PRINT_LOCK:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m  |  "
                          f"\033[96mVersion Info: {banner}\033[0m")
            except Exception:
                with PRINT_LOCK:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m")
        sock.close()
    except socket.error:
        pass

def worker():
    """The job for each thread. It takes a port from the queue and scans it."""
    while not PORT_QUEUE.empty():
        port = PORT_QUEUE.get()
        scan_port(port)
        PORT_QUEUE.task_done()

# --- Main Program ---

BANNER = r"""
  
   _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/ 

"""
print(BANNER)
print("          Welcome to Aura-sec v0.5.2")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)

scan_choice = main_menu()

if scan_choice == '1':
    TARGET_IP = get_target()
    port_range = get_ports()

    for p in port_range:
        PORT_QUEUE.put(p)

    num_threads = 100
    thread_list = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
        thread.start()

    PORT_QUEUE.join()

    for thread in thread_list:
        thread.join()

    print("-" * 50)
    print("[*] Scan complete.")

elif scan_choice == '2':
    print("\n[!] The Anonymous Scan feature is coming in a future version!")
    print("    We will build this in Phase 2 using a proxy like Tor.")
else:
    print("\n[!] Invalid choice. Please run the program again and select 1 or 2.")

print("\nThank you for using Aura-sec!")