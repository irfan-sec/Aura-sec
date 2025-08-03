"""
Aura-sec v2.0
A unique and easy-to-use scanner for the community.
Refactored for clarity, quality, and extensibility.
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
results = []

# --- Banner Grabbing Helper Functions ---

def get_http_banner(sock):
    """Sends a specific probe for HTTP and parses the banner."""
    try:
        sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + TARGET_IP.encode() + b'\r\n\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        lines = response.split('\r\n')
        for line in lines:
            if 'Server:' in line:
                return line.split(': ')[1].strip()
        # If no server header, return the first line
        if lines:
            return lines[0].strip()
    except socket.error:
        return "N/A"
    return ""

def get_generic_banner(sock):
    """Tries a generic banner grab for non-HTTP services."""
    try:
        return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except socket.error:
        return ""

# --- Core Scanner Functions ---

def scan_port(port):
    """Connects to a port and dispatches to the correct banner grabber."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((TARGET_IP, port)) == 0:
            banner = ""
            if port == 80:
                banner = get_http_banner(sock)
            elif port == 443:
                banner = "HTTPS"
            else:
                banner = get_generic_banner(sock)
            
            with PRINT_LOCK:
                results.append((port, banner))
        sock.close()
    except socket.error:
        pass

def worker():
    """The job for each thread."""
    while not PORT_QUEUE.empty():
        port = PORT_QUEUE.get()
        scan_port(port)
        PORT_QUEUE.task_done()

# --- UI and Main Logic Functions ---

def main_menu():
    """Displays the main menu and gets the user's choice."""
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan (Coming Soon!)")
    return input("Enter your choice (1 or 2): ")

def get_target():
    """Gets the target IP address from the user."""
    return input("Please enter the target IP address: ")

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

def display_results_and_save():
    """Prints results to the screen and handles saving to a file."""
    print("-" * 50)
    print("[*] Scan complete.")
    if results:
        print(f"[*] Found {len(results)} open ports:")
        sorted_results = sorted(results, key=lambda x: x[0])
        for port, banner in sorted_results:
            if banner:
                print(f"\033[92m[+] Port {port} is OPEN\033[0m  |  "
                      f"\033[96mVersion Info: {banner}\033[0m")
            else:
                print(f"\033[92m[+] Port {port} is OPEN\033[0m")
        
        save = input("\nDo you want to save the results to a file? (y/n): ").lower()
        if save == 'y':
            filename = input("Enter filename (e.g., scan_results.txt): ")
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Scan results for target: {TARGET_IP}\n")
                    f.write("-" * 50 + "\n")
                    for port, banner in sorted_results:
                        f.write(f"Port {port}: OPEN | Version: {banner}\n")
                print(f"[+] Results saved to {filename}")
            except IOError as e:
                print(f"[!] Could not save results: {e}")
    else:
        print("[*] No open ports found.")

def main():
    """Main function to run the scanner."""
    global TARGET_IP # pylint: disable=global-statement
    BANNER = r"""

   _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/ 

    """
    print(BANNER)
    print("           Welcome to Aura-sec v2.0")
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
            
            num_threads = 100
            thread_list = []
            for _ in range(num_threads):
                thread = threading.Thread(target=worker)
                thread_list.append(thread)
                thread.start()
            
            PORT_QUEUE.join()
            
            display_results_and_save()

        elif scan_choice == '2':
            print("\n[!] The Anonymous Scan feature is coming in a future version!")
        else:
            print("\n[!] Invalid choice. Please run the program again.")
    except KeyboardInterrupt:
        print("\n[!] Exiting program (Ctrl+C detected).")
    
    print("\nThank you for using Aura-sec!")

if __name__ == "__main__":
    main()
