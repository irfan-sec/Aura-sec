"""
Aura-sec v2.5.0
A unique and easy-to-use scanner for the community.
Enhanced with advanced service detection, stealth scanning, and multiple output formats.
"""
import sys
import socket
import threading
from queue import Queue
import ftplib # For FTP anonymous login check
from tqdm import tqdm
import json
import csv
import ssl
import datetime
import re
import random
import time

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
SCAN_START_TIME = None
STEALTH_MODE = False
SCAN_DELAY = 0  # Delay between scans in seconds

# Common service ports and their typical responses
SERVICE_SIGNATURES = {
    22: {"name": "SSH", "probe": "", "pattern": r"SSH-(\d+\.\d+)"},
    23: {"name": "Telnet", "probe": "", "pattern": r"login:|Username:|Password:"},
    25: {"name": "SMTP", "probe": "", "pattern": r"220.*SMTP"},
    53: {"name": "DNS", "probe": "", "pattern": r""},
    110: {"name": "POP3", "probe": "", "pattern": r"\+OK"},
    143: {"name": "IMAP", "probe": "", "pattern": r"\* OK"},
    993: {"name": "IMAPS", "probe": "", "pattern": r"\* OK"},
    995: {"name": "POP3S", "probe": "", "pattern": r"\+OK"},
    3389: {"name": "RDP", "probe": "", "pattern": r""},
    5432: {"name": "PostgreSQL", "probe": "", "pattern": r""},
    3306: {"name": "MySQL", "probe": "", "pattern": r""},
    1433: {"name": "MSSQL", "probe": "", "pattern": r""},
}

# --- Functions ---
# main_menu, get_target, get_ports stay the same...
def main_menu():
    """Displays the main menu and gets the user's choice."""
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan (Tor)")
    print("3. Stealth Scan")
    choice = input("Enter your choice (1-3): ")
    return choice

def get_stealth_options():
    """Configure stealth scan options."""
    global STEALTH_MODE, SCAN_DELAY, NUM_THREADS
    
    STEALTH_MODE = True
    print("\n[*] Configuring stealth scan options...")
    
    # Reduce threads for stealth
    NUM_THREADS = 20
    
    # Get scan delay
    try:
        delay = input("Enter scan delay in seconds (0.1-5.0, default 1.0): ")
        SCAN_DELAY = float(delay) if delay else 1.0
        SCAN_DELAY = max(0.1, min(5.0, SCAN_DELAY))  # Clamp between 0.1 and 5.0
    except ValueError:
        SCAN_DELAY = 1.0
    
    print(f"[*] Stealth mode enabled: {NUM_THREADS} threads, {SCAN_DELAY}s delay")

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
        
        # Extract server information and web technologies
        server_info = ""
        tech_info = []
        
        for line_item in lines:
            if 'Server:' in line_item:
                server_info = line_item.split(': ')[1].strip()
            elif 'X-Powered-By:' in line_item:
                tech_info.append(line_item.split(': ')[1].strip())
            elif 'X-AspNet-Version:' in line_item:
                tech_info.append("ASP.NET " + line_item.split(': ')[1].strip())
        
        result = server_info
        if tech_info:
            result += f" [{', '.join(tech_info)}]"
        
        if not result and lines:
            return lines[0].strip()
        return result
    except socket.error:
        pass
    return ""

def get_https_banner(sock):
    """Get banner from HTTPS port with SSL certificate info."""
    try:
        # Wrap socket with SSL
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with context.wrap_socket(sock, server_hostname=TARGET_IP) as ssock:
            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                common_name = subject.get('commonName', 'Unknown')
                issuer_org = issuer.get('organizationName', 'Unknown')
                return f"HTTPS - CN: {common_name}, Issuer: {issuer_org}"
            else:
                return "HTTPS (No certificate info)"
    except Exception:
        return "HTTPS"

def get_ssh_banner(sock):
    """Get SSH version banner."""
    try:
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if 'SSH' in banner:
            return f"SSH - {banner}"
    except socket.error:
        pass
    return ""

def get_smtp_banner(sock):
    """Get SMTP banner."""
    try:
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if '220' in banner:
            return f"SMTP - {banner.split('220 ')[1] if '220 ' in banner else banner}"
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
    """Handle the connection and dispatch to the correct banner/vulnerability check."""
    if port == 80:
        return get_http_banner(sock)
    elif port == 443:
        return get_https_banner(sock)
    elif port == 21:
        # If the port is FTP, run our vulnerability check
        if check_ftp_anonymous(TARGET_IP):
            return "FTP - VULNERABLE: Anonymous login enabled!"
        return f"FTP - {get_generic_banner(sock)}"
    elif port == 22:
        return get_ssh_banner(sock)
    elif port == 25:
        return get_smtp_banner(sock)
    elif port in SERVICE_SIGNATURES:
        service_name = SERVICE_SIGNATURES[port]["name"]
        banner = get_generic_banner(sock)
        return f"{service_name} - {banner}" if banner else service_name
    else:
        # For all other ports, do a generic banner grab
        banner = get_generic_banner(sock)
        return banner if banner else "Unknown service"

def scan_port(port):
    """Scans a single port and grabs a banner if possible using appropriate probes."""
    sock = None
    try:
        # Add stealth delay if enabled
        if STEALTH_MODE and SCAN_DELAY > 0:
            time.sleep(random.uniform(0.1, SCAN_DELAY))
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(2)  # Slightly longer timeout for banner grabbing
        
        if sock.connect_ex((TARGET_IP, port)) == 0:
            port_banner = handle_port_connection(sock, port)
            results.append((port, port_banner))
        
        if sock:
            sock.close()
    except socket.error:
        if sock:
            sock.close()

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

def save_results_txt(filename, sorted_results, scan_stats):
    """Save results in text format."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"Aura-sec Scan Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target: {TARGET_IP}\n")
        f.write(f"Scan Date: {scan_stats['start_time']}\n")
        f.write(f"Duration: {scan_stats['duration']:.2f} seconds\n")
        f.write(f"Ports Scanned: {scan_stats['ports_scanned']}\n")
        f.write(f"Open Ports: {len(sorted_results)}\n")
        f.write("-" * 50 + "\n\n")
        
        for port_result, banner_result in sorted_results:
            f.write(f"Port {port_result}: OPEN | Service: {banner_result}\n")

def save_results_json(filename, sorted_results, scan_stats):
    """Save results in JSON format."""
    data = {
        "scan_info": {
            "target": TARGET_IP,
            "start_time": scan_stats['start_time'],
            "duration": scan_stats['duration'],
            "ports_scanned": scan_stats['ports_scanned'],
            "scanner": "Aura-sec v2.5.0"
        },
        "results": []
    }
    
    for port_result, banner_result in sorted_results:
        data["results"].append({
            "port": port_result,
            "status": "open",
            "service": banner_result
        })
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def save_results_csv(filename, sorted_results, scan_stats):
    """Save results in CSV format."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Status', 'Service', 'Banner'])
        for port_result, banner_result in sorted_results:
            writer.writerow([port_result, 'OPEN', banner_result, banner_result])

def display_results_and_save():
    """Display scan results and handle saving to file."""
    scan_stats = get_scan_statistics()
    
    print("-" * 50)
    print("[*] Scan complete.")
    print(f"[*] Scan duration: {scan_stats['duration']:.2f} seconds")
    
    if results:
        print(f"[*] Found {len(results)} open ports:")
        sorted_results = sorted(results, key=lambda x: x[0])
        
        for port_result, banner_result in sorted_results:
            if banner_result:
                print(f"\033[92m[+] Port {port_result} is OPEN\033[0m  |  "
                      f"\033[96mService: {banner_result}\033[0m")
            else:
                print(f"\033[92m[+] Port {port_result} is OPEN\033[0m")
        
        save_results = input("\nDo you want to save the results to a file? (y/n): ").lower()
        if save_results == 'y':
            print("\nSelect output format:")
            print("1. Text (.txt)")
            print("2. JSON (.json)")
            print("3. CSV (.csv)")
            format_choice = input("Enter choice (1-3): ")
            
            base_filename = input("Enter base filename (without extension): ")
            if not base_filename:
                base_filename = f"aura_scan_{TARGET_IP}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            try:
                if format_choice == '1':
                    filename = f"{base_filename}.txt"
                    save_results_txt(filename, sorted_results, scan_stats)
                elif format_choice == '2':
                    filename = f"{base_filename}.json"
                    save_results_json(filename, sorted_results, scan_stats)
                elif format_choice == '3':
                    filename = f"{base_filename}.csv"
                    save_results_csv(filename, sorted_results, scan_stats)
                else:
                    print("[!] Invalid choice. Saving as text format.")
                    filename = f"{base_filename}.txt"
                    save_results_txt(filename, sorted_results, scan_stats)
                
                print(f"[+] Results saved to {filename}")
            except (OSError, IOError) as exc:
                print(f"[!] Could not save results: {exc}")
    else:
        print("[*] No open ports found.")

def check_ftp_anonymous(ip_address):
    """Tries to log in to an FTP server at the given IP anonymously."""
    try:
        ftp = ftplib.FTP(ip_address, timeout=2)
        ftp.login('anonymous', '')
        ftp.quit()
        return True
    except ftplib.all_errors:  # <-- Use specific FTP exception
        return False

# --- Main Program ---
# ... (BANNER and welcome message stay the same) ...
BANNER = r"""


   ('-.                 _  .-')     ('-.               .-')      ('-.              
  ( OO ).-.            ( \( -O )   ( OO ).-.          ( OO ).  _(  OO)             
  / . --. / ,--. ,--.   ,------.   / . --. /         (_)---\_)(,------.   .-----.  
  | \-.  \  |  | |  |   |   /`. '  | \-.  \    .-')  /    _ |  |  .---'  '  .--./  
.-'-'  |  | |  | | .-') |  /  | |.-'-'  |  | _(  OO) \  :` `.  |  |      |  |('-.  
 \| |_.'  | |  |_|( OO )|  |_.' | \| |_.'  |(,------. '..`''.)(|  '--.  /_) |OO  ) 
  |  .-.  | |  | | `-' /|  .  '.'  |  .-.  | '------'.-._)   \ |  .--'  ||  |`-'|  
  |  | |  |('  '-'(_.-' |  |\  \   |  | |  |         \       / |  `---.(_'  '--'\  
  `--' `--'  `-----'    `--' '--'  `--' `--'          `-----'  `------'   `-----'  

"""
print(BANNER)
print("           Welcome to Aura-sec v2.5.0")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)


try:
    scan_choice = main_menu()

    if scan_choice in ['1', '3']:  # Normal or Stealth scan
        if scan_choice == '3':
            get_stealth_options()
        
        TARGET_IP = get_target()
        port_range = get_ports()
        
        scan_type = "STEALTH" if scan_choice == '3' else "Normal"
        print(f"\n[*] Starting {scan_type} Scan on target: {TARGET_IP}...")
        
        # Initialize scan timing
        SCAN_START_TIME = time.time()
        
        # Convert range to list to get the total count for the progress bar
        ports_to_scan = list(port_range)
        for p in ports_to_scan:
            PORT_QUEUE.put(p)

        # Setup the progress bar object
        pbar = tqdm(total=len(ports_to_scan), desc=f"Scanning Ports ({scan_type})")

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

            # Initialize scan timing
            SCAN_START_TIME = time.time()

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
        print("\n[!] Invalid choice. Please run the program again and select 1, 2, or 3.")
except KeyboardInterrupt:
    print("\n[!] Exiting program (Ctrl+C detected).")

print("\nThank you for using Aura-sec!")
# End of main program
# This is the end of the aurasec.py file.
