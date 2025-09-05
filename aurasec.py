"""
Aura-sec v2.5.1
A unique and easy-to-use scanner for the community.
Enhanced with advanced service detection, stealth scanning, and multiple output formats.
"""
import sys
import socket
import threading
from queue import Queue
import ftplib  # For FTP anonymous login check
import json
import csv
import ssl
import datetime
import re
import random
import time
import urllib.request
import urllib.parse
import urllib.error

try:
    import socks
except ImportError:
    print("[!] PySocks not found. Please install it using: pip install PySocks")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[!] tqdm not found. Please install it using: pip install tqdm")
    sys.exit(1)

# --- Global variables ---
TARGET_IP = ""
PORT_QUEUE = Queue()
PRINT_LOCK = threading.Lock()
NUM_THREADS = 100  # Default number of threads for normal scanning
results = []  # A new list to store results (port and banner)
SCAN_START_TIME = None
STEALTH_MODE = False
SCAN_DELAY = 0  # Delay between scans in seconds
SHODAN_API_KEY = None
USE_SHODAN = False

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

# Common web application signatures
WEB_SIGNATURES = [
    (r"Server:\s*Apache", "Apache HTTP Server"),
    (r"Server:\s*nginx", "Nginx Web Server"),
    (r"Server:\s*Microsoft-IIS", "Microsoft IIS"),
    (r"X-Powered-By:\s*PHP", "PHP"),
    (r"X-Powered-By:\s*ASP\.NET", "ASP.NET"),
    (r"Set-Cookie:.*JSESSIONID", "Java/Tomcat"),
    (r"Set-Cookie:.*PHPSESSID", "PHP"),
    (r"WordPress", "WordPress CMS"),
    (r"Drupal", "Drupal CMS"),
    (r"Joomla", "Joomla CMS"),
]

# --- Functions ---
def main_menu():
    """Displays the main menu and gets the user's choice."""
    print("\nPlease select the type of scan:")
    print("1. Normal Scan")
    print("2. Anonymous Scan (Tor)")
    print("3. Stealth Scan")
    print("4. Intelligence Scan (with Shodan)")
    choice = input("Enter your choice (1-4): ")
    return choice

def configure_shodan():
    """Configure Shodan API integration."""
    global SHODAN_API_KEY, USE_SHODAN

    use_shodan = input("\nEnable Shodan integration for additional intelligence? (y/n): ").lower()
    if use_shodan == 'y':
        api_key = input("Enter your Shodan API key (or press Enter to skip): ").strip()
        if api_key:
            SHODAN_API_KEY = api_key
            USE_SHODAN = True
            print("[+] Shodan integration enabled")
            return True
        print("[-] Shodan integration skipped")
    return False

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
            print(f"[!] Error: Could not resolve '{target_input}'. Please check the name and your connection.")

def query_shodan(ip):
    """Query Shodan API for additional information about the target."""
    if not USE_SHODAN or not SHODAN_API_KEY:
        return None

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())

        shodan_info = {
            "organization": data.get("org", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": list(data.get("vulns", [])) if data.get("vulns") else [],
            "tags": data.get("tags", [])
        }
        return shodan_info
    except Exception:
        return None

def detect_web_technologies(response_headers):
    """Detect web technologies from HTTP response headers."""
    technologies = []
    full_response = " ".join(response_headers.split('\r\n'))

    for pattern, tech_name in WEB_SIGNATURES:
        if re.search(pattern, full_response, re.IGNORECASE):
            technologies.append(tech_name)

    return technologies

def analyze_ssl_certificate(ip, ssl_port=443):
    """Analyze SSL certificate for vulnerabilities and information."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, ssl_port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)

                if cert:
                    # Extract certificate information
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))

                    # Check certificate validity
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')

                    # Check for weak signature algorithms
                    cert_info = {
                        'common_name': subject.get('commonName', 'Unknown'),
                        'issuer_org': issuer.get('organizationName', 'Unknown'),
                        'valid_from': not_before,
                        'valid_to': not_after,
                        'serial_number': cert.get('serialNumber', 'Unknown'),
                        'version': cert.get('version', 'Unknown'),
                        'signature_algorithm': 'Unknown',  # Would need additional parsing
                        'san': cert.get('subjectAltName', [])
                    }

                    # Basic vulnerability checks
                    vulnerabilities = []
                    if not_after:
                        try:
                            expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            if expiry < datetime.datetime.now():
                                vulnerabilities.append("Certificate expired")
                        except ValueError:
                            pass

                    cert_info['vulnerabilities'] = vulnerabilities
                    return cert_info

    except Exception:
        pass
    return None

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
    """Get banner from HTTP port with enhanced web technology detection."""
    try:
        http_request = (b'GET / HTTP/1.1\r\nHost: ' + TARGET_IP.encode() + 
                       b'\r\nUser-Agent: Aura-sec/2.5.0\r\n\r\n')
        sock.send(http_request)
        response = sock.recv(4096).decode('utf-8', errors='ignore')

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

        # Detect additional web technologies
        detected_tech = detect_web_technologies(response)
        tech_info.extend(detected_tech)

        # Remove duplicates
        tech_info = list(set(tech_info))

        result = f"HTTP - {server_info}" if server_info else "HTTP"
        if tech_info:
            result += f" [{', '.join(tech_info)}]"

        if not server_info and lines:
            status_line = lines[0].strip()
            if "HTTP/" in status_line:
                result = f"HTTP - {status_line}"

        return result
    except socket.error:
        pass
    return "HTTP"

def get_https_banner(sock):
    """Get banner from HTTPS port with SSL certificate analysis."""
    try:
        cert_info = analyze_ssl_certificate(TARGET_IP, 443)
        if cert_info:
            result = f"HTTPS - CN: {cert_info['common_name']}, Issuer: {cert_info['issuer_org']}"
            if cert_info.get('vulnerabilities'):
                result += f" [VULN: {', '.join(cert_info['vulnerabilities'])}]"
            return result
        return "HTTPS"
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

def check_ftp_anonymous(ip_address):
    """Tries to log in to an FTP server at the given IP anonymously."""
    try:
        ftp = ftplib.FTP(ip_address, timeout=2)
        ftp.login('anonymous', '')
        ftp.quit()
        return True
    except ftplib.all_errors:
        return False

def handle_port_connection(sock, conn_port):
    """Handle the connection and dispatch to the correct banner/vulnerability check."""
    if conn_port == 80:
        return get_http_banner(sock)
    elif conn_port == 443:
        return get_https_banner(sock)
    elif conn_port == 21:
        # If the port is FTP, run our vulnerability check
        if check_ftp_anonymous(TARGET_IP):
            return "FTP - VULNERABLE: Anonymous login enabled!"
        return f"FTP - {get_generic_banner(sock)}"
    elif conn_port == 22:
        return get_ssh_banner(sock)
    elif conn_port == 25:
        return get_smtp_banner(sock)
    elif conn_port in SERVICE_SIGNATURES:
        service_name = SERVICE_SIGNATURES[conn_port]["name"]
        banner = get_generic_banner(sock)
        return f"{service_name} - {banner}" if banner else service_name
    else:
        # For all other ports, do a generic banner grab
        banner = get_generic_banner(sock)
        return banner if banner else "Unknown service"

def scan_udp_port(udp_port):
    """Scan a single UDP port."""
    try:
        # Add stealth delay if enabled
        if STEALTH_MODE and SCAN_DELAY > 0:
            time.sleep(random.uniform(0.1, SCAN_DELAY))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        # Send a generic probe
        try:
            sock.sendto(b'', (TARGET_IP, udp_port))
            response = sock.recv(1024)
            # If we get a response, the port is likely open
            service_name = SERVICE_SIGNATURES.get(udp_port, {}).get("name", "UDP service")
            results.append((udp_port, f"{service_name} (UDP)"))
        except socket.timeout:
            # UDP timeout doesn't mean the port is closed, but we can't determine if it's open
            pass
        except ConnectionResetError:
            # Port is definitely closed
            pass
        finally:
            sock.close()
    except Exception:
        pass

def get_scan_type():
    """Get scan type (TCP or UDP)."""
    print("\nSelect protocol to scan:")
    print("1. TCP (default)")
    print("2. UDP")
    print("3. Both TCP and UDP")
    choice = input("Enter choice (1-3, default 1): ")
    return choice if choice in ['1', '2', '3'] else '1'

def scan_port(scan_port_num):
    """Scans a single port and grabs a banner if possible using appropriate probes."""
    sock = None
    try:
        # Add stealth delay if enabled
        if STEALTH_MODE and SCAN_DELAY > 0:
            time.sleep(random.uniform(0.1, SCAN_DELAY))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(2)  # Slightly longer timeout for banner grabbing

        if sock.connect_ex((TARGET_IP, scan_port_num)) == 0:
            port_banner = handle_port_connection(sock, scan_port_num)
            results.append((scan_port_num, port_banner))

        if sock:
            sock.close()
    except socket.error:
        if sock:
            sock.close()

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

def get_scan_statistics():
    """Calculate scan statistics."""
    if SCAN_START_TIME is None:
        return {"duration": 0, "ports_scanned": 0, "start_time": "Unknown"}
    
    duration = time.time() - SCAN_START_TIME
    start_time = datetime.datetime.fromtimestamp(SCAN_START_TIME).strftime('%Y-%m-%d %H:%M:%S')
    
    return {
        "duration": duration,
        "ports_scanned": len(results),
        "start_time": start_time
    }

def save_results_txt(filename, sorted_results, scan_stats):
    """Save results in text format."""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("Aura-sec Scan Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target: {TARGET_IP}\n")
        f.write(f"Scan Date: {scan_stats['start_time']}\n")
        f.write(f"Duration: {scan_stats['duration']:.2f} seconds\n")
        f.write(f"Ports Scanned: {scan_stats['ports_scanned']}\n")
        f.write(f"Open Ports: {len(sorted_results)}\n")

        # Include Shodan information if available
        shodan_info = scan_stats.get('shodan_info')
        if shodan_info:
            f.write("\nShodan Intelligence:\n")
            f.write(f"Organization: {shodan_info['organization']}\n")
            f.write(f"ISP: {shodan_info['isp']}\n")
            f.write(f"Location: {shodan_info['city']}, {shodan_info['country']}\n")
            if shodan_info['vulns']:
                f.write(f"Known Vulnerabilities: {len(shodan_info['vulns'])}\n")
            if shodan_info['tags']:
                f.write(f"Tags: {', '.join(shodan_info['tags'])}\n")

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
            "scanner": "Aura-sec v2.5.1"
        },
        "results": []
    }

    # Include Shodan information if available
    shodan_info = scan_stats.get('shodan_info')
    if shodan_info:
        data["shodan_intelligence"] = shodan_info

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

    # Get Shodan information if enabled
    shodan_info = None
    if USE_SHODAN and SHODAN_API_KEY:
        print("\n[*] Querying Shodan for additional intelligence...")
        shodan_info = query_shodan(TARGET_IP)

    print("-" * 50)
    print("[*] Scan complete.")
    print(f"[*] Scan duration: {scan_stats['duration']:.2f} seconds")

    # Display Shodan information if available
    if shodan_info:
        print("\n[*] Shodan Intelligence:")
        print(f"    Organization: {shodan_info['organization']}")
        print(f"    ISP: {shodan_info['isp']}")
        print(f"    Location: {shodan_info['city']}, {shodan_info['country']}")
        if shodan_info['vulns']:
            print(f"    Known Vulnerabilities: {len(shodan_info['vulns'])}")
        if shodan_info['tags']:
            print(f"    Tags: {', '.join(shodan_info['tags'])}")

    if results:
        print(f"\n[*] Found {len(results)} open ports:")
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
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                base_filename = f"aura_scan_{TARGET_IP}_{timestamp}"

            # Include Shodan information in scan stats
            scan_stats['shodan_info'] = shodan_info

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

# --- Main Program ---
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
print("           Welcome to Aura-sec v2.5.1")
print("           A scanner by I R F A N")
print("     GitHub: https://github.com/irfan-sec")
print("-" * 50)

try:
    scan_choice = main_menu()

    if scan_choice in ['1', '3', '4']:  # Normal, Stealth, or Intelligence scan
        if scan_choice == '3':
            get_stealth_options()
        elif scan_choice == '4':
            configure_shodan()

        TARGET_IP = get_target()

        # Get protocol choice
        protocol_choice = get_scan_type()
        port_range = get_ports()

        scan_type = {"1": "Normal", "3": "STEALTH", "4": "INTELLIGENCE"}[scan_choice]
        protocol_name = {"1": "TCP", "2": "UDP", "3": "TCP+UDP"}[protocol_choice]

        print(f"\n[*] Starting {scan_type} {protocol_name} Scan on target: {TARGET_IP}...")

        # Initialize scan timing
        SCAN_START_TIME = time.time()

        # Convert range to list to get the total count for the progress bar
        ports_to_scan = list(port_range)

        # For combined scan, we'll scan both TCP and UDP
        if protocol_choice == '3':
            total_ports = len(ports_to_scan) * 2  # TCP + UDP
            for p in ports_to_scan:
                PORT_QUEUE.put(('tcp', p))
                PORT_QUEUE.put(('udp', p))
        else:
            total_ports = len(ports_to_scan)
            protocol = 'tcp' if protocol_choice == '1' else 'udp'
            for p in ports_to_scan:
                PORT_QUEUE.put((protocol, p))

        # Setup the progress bar object
        pbar = tqdm(total=total_ports, desc=f"Scanning {protocol_name} Ports ({scan_type})")

        # Enhanced worker function that handles both TCP and UDP
        def worker_with_progress():
            """Worker that handles both TCP and UDP scanning with progress."""
            while not PORT_QUEUE.empty():
                try:
                    protocol, port_worker = PORT_QUEUE.get()
                    if protocol == 'tcp':
                        scan_port(port_worker)
                    elif protocol == 'udp':
                        scan_udp_port(port_worker)
                    PORT_QUEUE.task_done()
                    pbar.update(1)
                except Exception:
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

                ports_to_scan = list(port_range)
                for p in ports_to_scan:
                    PORT_QUEUE.put(p)

                # Using fewer threads is generally better and safer for the Tor network
                NUM_THREADS = 20
                print(f"[*] Using {NUM_THREADS} threads for anonymous scan.")

                # Setup the progress bar
                pbar = tqdm(total=len(ports_to_scan), desc="Anonymous TCP Scan")

                def anonymous_worker():
                    """Worker for anonymous scanning."""
                    while not PORT_QUEUE.empty():
                        try:
                            port_worker = PORT_QUEUE.get()
                            scan_port(port_worker)
                            PORT_QUEUE.task_done()
                            pbar.update(1)
                        except Exception:
                            PORT_QUEUE.task_done()
                            pbar.update(1)

                thread_list = []
                for _ in range(NUM_THREADS):
                    thread = threading.Thread(target=anonymous_worker)
                    thread_list.append(thread)
                    thread.start()

                PORT_QUEUE.join()
                pbar.close()

                # This calls your existing results and save logic
                display_results_and_save()

        else:
            print("\n[!] Error: Tor SOCKS proxy not found.")
            print("    Please ensure the Tor service (tor.exe or Linux service) is running.")
    else:
        print("\n[!] Invalid choice. Please run the program again and select 1-4.")
except KeyboardInterrupt:
    print("\n[!] Exiting program (Ctrl+C detected).")
    sys.exit(0)

print("\nThank you for using Aura-sec!")
