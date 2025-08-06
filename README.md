# Aura-sec 🛡️

![Version](https://img.shields.io/badge/version-v2.2-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A unique and easy-to-use network port scanner designed for the cybersecurity community. This project is a learning tool built to understand the fundamentals of network reconnaissance, multi-threading, and operational security.

---

## Key Features

* **Interactive Menu:** Easy-to-use command-line interface.
* **Multi-threaded Scanning:** High-speed scanning using multiple threads.
* **Normal & Anonymous Modes:** Choose between a direct scan or an anonymous scan routed through the Tor network.
* **Port Range Selection:** Scan common ports or specify a custom range.
* **Hostname Resolution:** Accepts IP addresses or hostnames (e.g., `google.com`) as a target.
* **File Output:** Save your scan results to a text file for reporting.

## Installation

Aura-sec requires Python 3 and the `PySocks` library.

1.  Clone the repository:
    ```bash
    git clone [https://github.com/irfan-sec/Aura-sec.git](https://github.com/irfan-sec/Aura-sec.git)
    ```
2.  Navigate to the project directory:
    ```bash
    cd Aura-sec
    ```
3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the main script from your terminal:

```bash
python3 aurasec.py
````

The tool will guide you through an interactive menu to select your scan type, target, and port range. For Anonymous Scans, ensure the Tor service is running on your machine.

### Example Session

```
$ python3 aurasec.py

   _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/ 

            Welcome to Aura-sec v2.2
           A scanner by I R F A N
     GitHub: [https://github.com/irfan-sec](https://github.com/irfan-sec)
--------------------------------------------------

Please select the type of scan:
1. Normal Scan
2. Anonymous Scan (via Tor)
Enter your choice (1 or 2): 1

Please enter the target IP address or hostname: scanme.nmap.org
```

-----

## Project Roadmap

  - [x] Core multi-threaded scanning engine
  - [x] User-friendly interactive menu
  - [x] Hostname resolution
  - [x] Save results to file
  - [x] Basic Tor integration for anonymous scans
  - [ ] Add banner grabbing for more services
  - [ ] Add UDP scan functionality
  - [ ] Improve output formatting

## Contributing

This is a personal learning project, but suggestions and feedback are always welcome. Please feel free to open an issue or submit a pull request.

```
