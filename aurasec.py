"""
Aura-sec v1.3
A unique and easy-to-use scanner for the community.
Coded by I R F A N
GitHub: https://github.com/irfan-sec
"""
import socket
import threading
from queue import Queue

# --- Global variables ---
TARGET_IP = ""
PORT_QUEUE = Queue()
PRINT_LOCK = threading.Lock()
results = [] # A new list to store results (port and banner)

# --- Functions ---
# main_menu, get_target, get_ports stay the same...
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
        prompt = ("Select port range:\n1. Common Ports (1-1024)\n"
                  "2. Custom Range\nEnter choice (1 or 2): ")
        choice = input(prompt)
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
    """Scans a single port and grabs a banner if possible using appropriate probes."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        if sock.connect_ex((TARGET_IP, port)) == 0:
            banner = ""
            # --- New, Cleaner Logic ---
            if port == 80:
                # Send a specific probe for HTTP
                try:
                    sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + TARGET_IP.encode() + b'\r\n\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    lines = response.split('\r\n')
                    for line in lines:
                        if 'Server:' in line:
                            banner = line.split(': ')[1].strip()
                            break
                    if not banner and lines:
                        banner = lines[0].strip()
                except socket.error:
                    pass # Keep banner empty if probe fails
            elif port == 443:
                # We can't grab a banner from an encrypted port this simply, so we label it
                banner = "HTTPS"
            else:
                # Try a generic grab for all other "chatty" ports
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.error:
                    pass # Keep banner empty if grab fails
            
            results.append((port, banner)) # Add our findings to the results list
        sock.close()
    except socket.error:
        pass

def get_banner(sock, port):
    """Tries to grab a banner from an open port with smarter HTTP parsing."""
    banner = ""
    # Advanced probe for HTTP on port 80
    if port == 80:
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            lines = response.split('\r\n')
            
            # First, try to find a specific 'Server:' header
            for line in lines:
                if 'Server:' in line:
                    banner = line.split(': ')[1].strip()
                    break
            
            # If no 'Server:' header was found, use the first line of the response
            if not banner and lines:
                banner = lines[0].strip()

        except socket.error:
            banner = "N/A" # Could not get a banner
    # Standard grab for other ports
    else:
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.error:
            pass # No banner received
    return banner

def worker():
    """The job for each thread."""
    while not PORT_QUEUE.empty():
        port = PORT_QUEUE.get()
        scan_port(port)
        PORT_QUEUE.task_done()

# --- Main Program ---
# ... (BANNER and welcome message stay the same) ...
BANNER = r"""

   _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/ 

"""
print(BANNER)
print("           Welcome to Aura-sec v1.3")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)


try:
    scan_choice = main_menu()

    if scan_choice == '1':
        TARGET_IP = get_target()
        port_range = get_ports()
        
        print(f"\n[*] Starting Scan on target: {TARGET_IP}...")
        
        for p in port_range:
            PORT_QUEUE.put(p)

        try:
            NUM_THREADS = int(input("Enter number of threads (default 100): ") or "100")
            if NUM_THREADS < 1:
                NUM_THREADS = 100
        except ValueError:
            NUM_THREADS = 100

        thread_list = []
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=worker)
            thread_list.append(thread)
            thread.start()

        PORT_QUEUE.join()

        # --- New Results and Save Logic ---
        print("-" * 50)
        print("[*] Scan complete.")
        if results:
            print(f"[*] Found {len(results)} open ports:")
            # Sort results by port number
            sorted_results = sorted(results, key=lambda x: x[0])
            for port, banner in sorted_results:
                if banner:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m  |  \033[96mVersion Info: {banner}\033[0m")
                else:
                    print(f"\033[92m[+] Port {port} is OPEN\033[0m")
            
            save_results = input("\nDo you want to save the results to a file? (y/n): ").lower()
            if save_results == 'y':
                filename = input("Enter filename to save (e.g., scan_results.txt): ")
                try:
                    with open(filename, 'w') as f:
                        f.write(f"Scan results for target: {TARGET_IP}\n")
                        f.write("-" * 50 + "\n")
                        for port, banner in sorted_results:
                            f.write(f"Port {port}: OPEN | Version: {banner}\n")
                    print(f"[+] Results saved to {filename}")
                except Exception as e:
                    print(f"[!] Could not save results: {e}")
        else:
            print("[*] No open ports found.")

    elif scan_choice == '2':
        print("\n[!] The Anonymous Scan feature is coming in a future version!")
        print("    We will build this in Phase 2 using a proxy like Tor.")
    else:
        print("\n[!] Invalid choice. Please run the program again and select 1 or 2.")
except KeyboardInterrupt:
    print("\n[!] Exiting program (Ctrl+C detected).")


print("\nThank you for using Aura-sec!")
