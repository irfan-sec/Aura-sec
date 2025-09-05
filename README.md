# Aura-sec 🛡️

![Version](https://img.shields.io/badge/version-v2.5.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A powerful and feature-rich network port scanner designed for cybersecurity professionals and students. This enhanced version includes advanced service detection, intelligence gathering, stealth scanning, and comprehensive reporting capabilities.

---

## 🚀 Key Features

### Core Scanning Capabilities
* **Multi-Protocol Scanning:** TCP, UDP, and combined TCP+UDP scanning modes
* **Multi-threaded Performance:** High-speed scanning using configurable thread pools
* **Multiple Scan Modes:** Normal, Anonymous (Tor), Stealth, and Intelligence scanning
* **Port Range Flexibility:** Scan common ports (1-1024) or specify custom ranges
* **Hostname Resolution:** Accepts both IP addresses and hostnames as targets

### Advanced Service Detection
* **Enhanced Banner Grabbing:** Protocol-specific probes for HTTP/HTTPS, SSH, SMTP, FTP
* **Web Technology Detection:** Identifies web servers, frameworks, and CMS platforms
* **SSL/TLS Analysis:** Certificate information and basic vulnerability assessment
* **Service Fingerprinting:** Recognizes 12+ common services with signature database

### Intelligence Gathering
* **Shodan Integration:** Optional API integration for additional target intelligence
* **Vulnerability Detection:** FTP anonymous login, SSL certificate issues
* **Organizational Intelligence:** ISP, organization, and geographic information

### Stealth & Operational Security
* **Stealth Mode:** Configurable scan delays and reduced thread counts
* **Anonymous Scanning:** Tor network integration for anonymized reconnaissance  
* **Randomized Timing:** Evade basic rate limiting and detection systems

### Professional Reporting
* **Multiple Output Formats:** JSON, CSV, and enhanced text reports
* **Comprehensive Metadata:** Scan statistics, timing, and target information
* **Intelligence Integration:** Shodan data included in all output formats
* **Structured Data:** Machine-readable formats for integration with other tools

---

## 📦 Installation

Aura-sec requires Python 3.6+ and several dependencies:

1. Clone the repository:
   ```bash
   git clone https://github.com/irfan-sec/Aura-sec.git
   cd Aura-sec
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) For Shodan integration, obtain an API key from [shodan.io](https://shodan.io)

---

## 🎯 Usage

Run the scanner with:
```bash
python3 aurasec.py
```

### Scan Modes

1. **Normal Scan**: Standard TCP scanning with service detection
2. **Anonymous Scan**: Routes traffic through Tor network (requires Tor service)
3. **Stealth Scan**: Slower scanning with configurable delays to evade detection
4. **Intelligence Scan**: Enhanced scanning with Shodan API integration

### Protocol Options

* **TCP Only**: Traditional port scanning (default)
* **UDP Only**: UDP service discovery
* **Combined**: Both TCP and UDP scanning

### Example Session

```
$ python3 aurasec.py

           Welcome to Aura-sec v2.5.0
           A scanner by I R F A N
     GitHub: https://github.com/irfan-sec
--------------------------------------------------

Please select the type of scan:
1. Normal Scan
2. Anonymous Scan (Tor)
3. Stealth Scan  
4. Intelligence Scan (with Shodan)
Enter your choice (1-4): 4

Enable Shodan integration for additional intelligence? (y/n): y
Enter your Shodan API key: YOUR_API_KEY_HERE

Please enter the target IP address or hostname: example.com

Select protocol to scan:
1. TCP (default)
2. UDP
3. Both TCP and UDP
Enter choice (1-3): 1

Select port range:
1. Common Ports (1-1024)
2. Custom Range
Enter choice (1 or 2): 1

[*] Starting INTELLIGENCE TCP Scan on target: 93.184.216.34...
Scanning TCP Ports (INTELLIGENCE): 100%|████████| 1024/1024

[*] Querying Shodan for additional intelligence...
--------------------------------------------------
[*] Scan complete.
[*] Scan duration: 12.45 seconds

[*] Shodan Intelligence:
    Organization: Edgecast
    ISP: Verizon Digital Media Services
    Location: Norwell, United States

[*] Found 3 open ports:
[+] Port 80 is OPEN  |  Service: HTTP - nginx/1.18.0 [CloudFlare]
[+] Port 443 is OPEN  |  Service: HTTPS - CN: example.com, Issuer: DigiCert Inc
[+] Port 22 is OPEN  |  Service: SSH - OpenSSH_7.4

Do you want to save the results to a file? (y/n): y

Select output format:
1. Text (.txt)
2. JSON (.json)  
3. CSV (.csv)
Enter choice (1-3): 2

Enter base filename: example_scan
[+] Results saved to example_scan.json
```

---

## 🎓 Educational Value

This tool is designed to teach cybersecurity concepts including:

- **Network Reconnaissance**: Understanding how port scanning works
- **Service Enumeration**: Learning to identify and fingerprint network services
- **Operational Security**: Using anonymization and stealth techniques
- **Intelligence Gathering**: Integrating multiple data sources for reconnaissance
- **Vulnerability Assessment**: Basic security testing methodologies

---

## 🔧 Advanced Features

### Web Technology Detection
Automatically identifies:
- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, ASP.NET, Java)
- Content Management Systems (WordPress, Drupal, Joomla)
- Web frameworks and technologies

### SSL/TLS Analysis
- Certificate subject and issuer information
- Validity period checking
- Subject Alternative Names (SAN)
- Basic vulnerability detection (expired certificates)

### Shodan Integration
When enabled with a valid API key:
- Organization and ISP information
- Geographic location data
- Known vulnerabilities (CVEs)
- Additional open ports and services
- Security tags and classifications

### Output Formats

**JSON Format**: Machine-readable with full metadata
```json
{
  "scan_info": {
    "target": "example.com",
    "scanner": "Aura-sec v2.5.0",
    "duration": 12.45
  },
  "shodan_intelligence": {
    "organization": "Example Corp",
    "vulns": ["CVE-2021-1234"]
  },
  "results": [...]
}
```

**CSV Format**: Spreadsheet-compatible for analysis
```csv
Port,Status,Service,Banner
80,OPEN,HTTP - nginx/1.18.0,HTTP - nginx/1.18.0
443,OPEN,HTTPS - SSL cert,HTTPS - SSL cert
```

---

## 🛣️ Roadmap

### Completed ✅
- [x] Multi-threaded TCP scanning
- [x] Anonymous Tor integration  
- [x] Enhanced service detection
- [x] Multiple output formats
- [x] Shodan API integration
- [x] SSL/TLS analysis
- [x] Stealth scanning modes
- [x] UDP scanning capability
- [x] Web technology detection

### Planned 📋
- [ ] OS fingerprinting capabilities
- [ ] CVE database integration
- [ ] Nmap XML import/export
- [ ] Configuration file support
- [ ] Advanced vulnerability checks
- [ ] Custom scan profiles
- [ ] REST API interface

---

## ⚠️ Legal Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning networks they do not own or have explicit permission to test.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

