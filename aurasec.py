"""
Aura-sec v2.3
A unique and easy-to-use scanner for the community.
"""
import sys
import socket
import threading
from queue import Queue
from tqdm import tqdm

try:
    import socks
except ImportError:
    print("[!] PySocks not found. Please install it using: pip install PySocks")
    sys.exit(1)

# --- Global variables ---
TARGET_IP = ""
PORT_QUEUE = Queue()
PRINT_LOCK = threading.Lock()
NUM_THREADS = 100  # Default number of threads for normal scanning
results = [] # A new list to store results (port and banner)

# --- Functions ---
# main_menu, get_target, get_ports stay the same...
def main_menu():
    """Displays the main menu and gets the user's choice."""
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan")
    choice = input("Enter your choice (1 or 2): ")
    return choice

def get_target():
    """Gets the target from the user and resolves it to an IP address."""
    while True:
        target_input = input("Please enter the target IP address or hostname: ")
        try:
            # Try to resolve the hostname to an IP address.
            # If an IP is entered, it will return the IP itself.
            target_ip = socket.gethostbyname(target_input)
            print(f"\n[*] Resolving '{target_input}' to {target_ip}")
            return target_ip
        except socket.gaierror:
            # If it fails, it's an invalid hostname or IP
            print(f"[!] Error: Could not resolve '{target_input}'. "
                  "Please check the name and your connection.")

def get_custom_port_range():
    """Gets custom port range from user input."""
    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        return range(start_port, end_port + 1)
    except ValueError:
        print("[!] Invalid input. Please enter numbers only.")
        return None

def get_ports():
    """Gets the port scanning option and range from the user."""
    while True:
        prompt = ("Select port range:\n1. Common Ports (1-1024)\n"
                 "2. Custom Range\nEnter choice (1 or 2): ")
        choice = input(prompt)
        if choice == '1':
            return range(1, 1025)
        if choice == '2':
            custom_range = get_custom_port_range()
            if custom_range:
                return custom_range
            continue
        print("[!] Invalid choice. Please enter 1 or 2.")

def get_http_banner(sock):
    """Get banner from HTTP port."""
    try:
        sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + TARGET_IP.encode() + b'\r\n\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        lines = response.split('\r\n')
        for line_item in lines:
            if 'Server:' in line_item:
                return line_item.split(': ')[1].strip()
        if lines:
            return lines[0].strip()
    except socket.error:
        pass
    return ""

def get_generic_banner(sock):
    """Get banner from a generic port."""
    try:
        return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except socket.error:
        pass
    return ""

def handle_port_connection(sock, port):
    """Handle the connection to a port and return the banner if available."""
    if port == 80:
        return get_http_banner(sock)
    if port == 443:
        return "HTTPS"
    return get_generic_banner(sock)

def scan_port(port):
    """Scans a single port and grabs a banner if possible using appropriate probes."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        if sock.connect_ex((TARGET_IP, port)) == 0:
            port_banner = handle_port_connection(sock, port)
            results.append((port, port_banner)) # Add our findings to the results list
        sock.close()
    except socket.error:
        pass

def get_banner():
    """Unused placeholder for banner grabbing."""
    # Function intentionally left blank for future use

def check_tor_proxy():
    """Checks if the Tor SOCKS proxy is running on the default port 9050."""
    try:
        proxy_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_check.settimeout(1)
        # Try to connect to the local Tor proxy
        if proxy_check.connect_ex(('127.0.0.1', 9050)) == 0:
            proxy_check.close()
            return True
        proxy_check.close()
        return False
    except socket.error:
        return False

def worker():
    """The job for each thread."""
    while not PORT_QUEUE.empty():
        port_worker = PORT_QUEUE.get()
        scan_port(port_worker)
        PORT_QUEUE.task_done()

def display_results_and_save():
    """Display scan results and handle saving to file."""
    print("-" * 50)
    print("[*] Scan complete.")
    if results:
        print(f"[*] Found {len(results)} open ports:")
        sorted_results = sorted(results, key=lambda x: x[0])
        for port_result, banner_result in sorted_results:
            if banner_result:
                print(f"\033[92m[+] Port {port_result} is OPEN\033[0m  |  "
                      f"\033[96mVersion Info: {banner_result}\033[0m")
            else:
                print(f"\033[92m[+] Port {port_result} is OPEN\033[0m")
        save_results = input("\nDo you want to save the results to a file? (y/n): ").lower()
        if save_results == 'y':
            filename = input("Enter filename to save (e.g., scan_results.txt): ")
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Scan results for target: {TARGET_IP}\n")
                    f.write("-" * 50 + "\n")
                    for port_result, banner_result in sorted_results:
                        f.write(f"Port {port_result}: OPEN | Version: {banner_result}\n")
                print(f"[+] Results saved to {filename}")
            except (OSError, IOError) as exc:
                print(f"[!] Could not save results: {exc}")
    else:
        print("[*] No open ports found.")

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
print("           Welcome to Aura-sec v2.3")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)


try:
    scan_choice = main_menu()

    if scan_choice == '1':
        TARGET_IP = get_target()
        port_range = get_ports()
        print(f"\n[*] Starting Scan on target: {TARGET_IP}...")
        
        # Convert range to list to get the total count for the progress bar
        ports_to_scan = list(port_range)
        for p in ports_to_scan:
            PORT_QUEUE.put(p)

        # Setup the progress bar object
        pbar = tqdm(total=len(ports_to_scan), desc="Scanning Ports")

        # This is a new worker function defined inside main that can see the pbar
        def worker_with_progress():
            """Worker that also updates the progress bar."""
            while not PORT_QUEUE.empty():
                port_worker = PORT_QUEUE.get()
                scan_port(port_worker)
                PORT_QUEUE.task_done()
                pbar.update(1)

        # Create and start the threads with the new worker function
        thread_list = []
        for _ in range(NUM_THREADS):
            thread = threading.Thread(target=worker_with_progress)
            thread_list.append(thread)
            thread.start()

        # Wait for all ports in the queue to be processed
        PORT_QUEUE.join()

        # Close the progress bar cleanly after the scan is done
        pbar.close()

        display_results_and_save()

    elif scan_choice == '2':
        print("\n[*] Checking for Tor SOCKS proxy on 127.0.0.1:9050...")
        if check_tor_proxy():
            print("[+] Tor proxy found! Configuring scanner to use Tor...")

            # --- This is the magic that makes the scan anonymous ---
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            print("[+] Scanner is now anonymized. All traffic will go through Tor.")
            # --- End of magic ---

            # Now, we re-use the same logic from your normal scan
            TARGET_IP = get_target()
            port_range = get_ports()
            if port_range:
                print(f"\n[*] Starting ANONYMOUS Scan on target: {TARGET_IP}...")
                for p in port_range:
                    PORT_QUEUE.put(p)

                # Using fewer threads is generally better and safer for the Tor network
                NUM_THREADS = 20
                print(f"[*] Using {NUM_THREADS} threads for anonymous scan.")

                thread_list = []
                for _ in range(NUM_THREADS):
                    thread = threading.Thread(target=worker)
                    thread_list.append(thread)
                    thread.start()

                PORT_QUEUE.join()

                # This calls your existing results and save logic
                display_results_and_save()

        else:
            print("\n[!] Error: Tor SOCKS proxy not found.")
            print("    Please ensure the Tor service (tor.exe or Linux service) is running.")
    else:
        print("\n[!] Invalid choice. Please run the program again and select 1 or 2.")
except KeyboardInterrupt:
    print("\n[!] Exiting program (Ctrl+C detected).")

print("\nThank you for using Aura-sec!")
# End of main program
# This is the end of the aurasec.py file.
