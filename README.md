# Aura-sec 🛡️

![Version](https://img.shields.io/badge/version-v2.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A simple, unique, and extensible network port scanner designed for the cybersecurity community. This project is a learning tool built to understand the fundamentals of network reconnaissance.

---

## Key Features

* **Interactive Menu:** Easy-to-use command-line interface.
* **Normal Scan Mode:** For standard network reconnaissance.
* **Port Range Selection:** Scan all common ports or specify a custom range.
* **Banner Grabbing:** Identifies the service and version running on open ports.
* **Anonymous Scan Mode:** Route scans through a proxy like Tor for OpSec. *(Planned for future release)*

## Installation

Currently, the tool can be run directly from the source code. You will need Python 3.

1.  Clone the repository:
    ```bash
    git clone https://github.com/irfan-sec/Aura-sec.git
    ```
2.  Navigate to the project directory:
    ```bash
    cd Aura-sec
    ```

## Usage

Run the main script from your terminal:

```bash
python3 aurasec.py
```
---

## HELP
The tool will then guide you through an interactive menu to select your scan type, target, and port range.

Example
$ python3 aurasec.py
--------------------------------------------------
    _____                                  _________              
  /  _  \  __ ______________             /   _____/ ____   ____  
 /  /_\  \|  |  \_  __ \__  \    ______  \_____  \_/ __ \_/ ___\ 
/    |    \  |  /|  | \// __ \_ /_____/  /        \  ___/\  \___ 
\____|__  /____/ |__|  (____  /         /_______  /\___  >\___  >
        \/                  \/                  \/     \/     \/
--------------------------------------------------

Please select the type of scan:
1. Normal Scan
2. Anonymous Scan (Coming Soon!)
Enter your choice (1 or 2): 1

Please enter the target IP address: 10.129.95.232

Select port range:
1. Common Ports (1-1024)
2. Custom Range
Enter choice (1 or 2): 1

-------------------
