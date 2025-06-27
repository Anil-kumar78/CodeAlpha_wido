#!/usr/bin/env python3

import os
import sys
import argparse
import json
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import subprocess
import re
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich import print as rprint
from concurrent.futures import ThreadPoolExecutor
from security_checks import SecurityChecks
import dns.resolver
import socket
import requests
import time

class VulnerabilityScanner:
    def __init__(self, path: str, output: str, severity: str = "low", exclude: List[str] = None, max_workers: int = 4):
        self.path = Path(path)
        self.output = output
        self.severity = severity
        self.exclude = exclude or []
        self.console = Console()
        self.findings = []
        self.max_workers = max_workers
        self.security_checks = SecurityChecks()

    def check_sql_injection(self, content: str, filename: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        sql_patterns = [
            r"SELECT.*FROM.*WHERE.*=\s*'.*'",
            r"INSERT\s+INTO.*VALUES\s*\(.*\)",
            r"UPDATE.*SET.*WHERE.*=\s*'.*'",
            r"DELETE\s+FROM.*WHERE.*=\s*'.*'",
            r"UNION\s+SELECT",
            r"OR\s+'1'\s*=\s*'1'",
            r"OR\s+'1'\s*=\s*'1\s*--"
        ]
        
        for pattern in sql_patterns:
            for i, line in enumerate(content.split('\n'), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'file': filename,
                        'line': i,
                        'code': line.strip(),
                        'severity': 'high',
                        'description': 'Potential SQL injection vulnerability detected'
                    })
        return vulnerabilities

    def check_xss(self, content: str, filename: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        xss_patterns = [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"eval\s*\(",
            r"dangerouslySetInnerHTML",
            r"outerHTML\s*=",
            r"setTimeout\s*\(\s*['\"]",
            r"setInterval\s*\(\s*['\"]"
        ]
        
        for pattern in xss_patterns:
            for i, line in enumerate(content.split('\n'), 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'file': filename,
                        'line': i,
                        'code': line.strip(),
                        'severity': 'high',
                        'description': 'Potential XSS vulnerability detected'
                    })
        return vulnerabilities

    def check_command_injection(self, content: str, filename: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        cmd_patterns = [
            r"exec\s*\(",
            r"spawn\s*\(",
            r"system\s*\(",
            r"popen\s*\(",
            r"subprocess\.call",
            r"subprocess\.run",
            r"shell\s*=\s*True"
        ]
        
        for pattern in cmd_patterns:
            for i, line in enumerate(content.split('\n'), 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'file': filename,
                        'line': i,
                        'code': line.strip(),
                        'severity': 'critical'
                    })
        return vulnerabilities

    def check_path_traversal(self, content: str, filename: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        path_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"file:\/\/",
            r"\/etc\/passwd",
            r"C:\\Windows\\System32"
        ]
        
        for pattern in path_patterns:
            for i, line in enumerate(content.split('\n'), 1):
                if re.search(pattern, line):
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'file': filename,
                        'line': i,
                        'code': line.strip(),
                        'severity': 'high'
                    })
        return vulnerabilities

    def check_hardcoded_secrets(self, content: str, filename: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        secret_patterns = [
            r"password\s*=\s*['\"][\w\d@$!%*#?&]+['\"]",
            r"api[_-]?key\s*=\s*['\"][\w\d]+['\"]",
            r"secret\s*=\s*['\"][\w\d]+['\"]",
            r"token\s*=\s*['\"][\w\d]+['\"]"
        ]
        
        for pattern in secret_patterns:
            for i, line in enumerate(content.split('\n'), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Hardcoded Secrets',
                        'file': filename,
                        'line': i,
                        'code': line.strip(),
                        'severity': 'critical'
                    })
        return vulnerabilities

    def scan_file(self, file_path: Path) -> None:
        try:
            # Skip files larger than 10MB to prevent memory issues
            if file_path.stat().st_size > 10 * 1024 * 1024:
                self.console.print(f"[yellow]Skipping large file {file_path} (>10MB)[/yellow]")
                return

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Run all security checks
            checks = [
                self.check_sql_injection(content, str(file_path)),
                self.check_xss(content, str(file_path)),
                SecurityChecks.check_insecure_deserialization(content, str(file_path)),
                SecurityChecks.check_weak_crypto(content, str(file_path)),
                SecurityChecks.check_logic_flaws(content, str(file_path)),
                SecurityChecks.check_security_misconfigs(content, str(file_path)),
                SecurityChecks.check_race_conditions(content, str(file_path))
            ]
            
            for check_results in checks:
                self.findings.extend(check_results)
            
        except Exception as e:
            self.console.print(f"[red]Error scanning {file_path}: {str(e)}[/red]")

    def scan(self) -> None:
        if not self.path.exists():
            self.console.print(f"[red]Error: Path {self.path} does not exist[/red]")
            return

        files_to_scan = []
        for root, _, files in os.walk(self.path):
            for file in files:
                file_path = Path(root) / file
                
                # Skip excluded patterns and binary files
                if any(exclude in str(file_path) for exclude in self.exclude):
                    continue
                if file.endswith(('.pyc', '.jpg', '.png', '.gif', '.pdf', '.zip')):
                    continue
                    
                files_to_scan.append(file_path)

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files_to_scan))
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                for _ in executor.map(self.scan_file, files_to_scan):
                    progress.update(task, advance=1)

    def generate_report(self) -> None:
        # Filter findings based on severity
        severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_severity = severity_levels[self.severity.lower()]
        
        filtered_findings = [
            f for f in self.findings 
            if severity_levels[f['severity'].lower()] >= min_severity
        ]

        # Group findings by type
        findings_by_type = {}
        for finding in filtered_findings:
            if finding['type'] not in findings_by_type:
                findings_by_type[finding['type']] = []
            findings_by_type[finding['type']].append(finding)

        # Create a rich table for the report
        table = Table(title="Vulnerability Scan Report")
        table.add_column("Type", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Line", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="magenta")
        table.add_column("Code", style="blue")

        for vuln_type, findings in findings_by_type.items():
            for finding in findings:
                table.add_row(
                    finding['type'],
                    finding['file'],
                    str(finding['line']),
                    finding['severity'].upper(),
                    finding.get('description', ''),
                    finding['code']
                )

        # Print to console
        self.console.print(table)

        # Save to HTML file
        if self.output:
            html_content = f"""
            <html>
            <head>
                <title>Vulnerability Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .critical {{ color: red; font-weight: bold; }}
                    .high {{ color: orange; }}
                    .medium {{ color: #FFD700; }}
                    .low {{ color: green; }}
                    .summary {{ margin: 20px 0; }}
                    .vuln-type {{ margin-top: 30px; }}
                </style>
            </head>
            <body>
                <h1>Vulnerability Scan Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <ul>
                        <li>Total vulnerabilities found: {len(filtered_findings)}</li>
                        <li>Critical: {len([f for f in filtered_findings if f['severity'] == 'critical'])}</li>
                        <li>High: {len([f for f in filtered_findings if f['severity'] == 'high'])}</li>
                        <li>Medium: {len([f for f in filtered_findings if f['severity'] == 'medium'])}</li>
                        <li>Low: {len([f for f in filtered_findings if f['severity'] == 'low'])}</li>
                    </ul>
                </div>
            """
            
            # Group findings by type in the HTML report
            for vuln_type, findings in findings_by_type.items():
                html_content += f"""
                <div class="vuln-type">
                    <h3>{vuln_type}</h3>
                    <table>
                        <tr>
                            <th>File</th>
                            <th>Line</th>
                            <th>Severity</th>
                            <th>Description</th>
                            <th>Code</th>
                        </tr>
                """
                
                for finding in findings:
                    html_content += f"""
                        <tr>
                            <td>{finding['file']}</td>
                            <td>{finding['line']}</td>
                            <td class="{finding['severity'].lower()}">{finding['severity'].upper()}</td>
                            <td>{finding.get('description', '')}</td>
                            <td><pre>{finding['code']}</pre></td>
                        </tr>
                    """
                
                html_content += "</table></div>"
            
            html_content += """
            </body>
            </html>
            """
            
            with open(self.output, 'w') as f:
                f.write(html_content)
            self.console.print(f"\n[green]Report saved to {self.output}[/green]")

# --- SubdomainFinder class ---
class SubdomainFinder:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'admin', 'blog', 'dev', 'test', 'staging', 'api', 'shop',
            'secure', 'vpn', 'm', 'mobile', 'beta', 'demo', 'portal', 'docs', 'support'
        ]

    def dns_lookup(self, subdomain):
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            for answer in answers:
                self.subdomains.add(full_domain)
                print(f"[+] Found: {full_domain} -> {answer}")
        except:
            pass

    def check_common_subdomains(self):
        print("\n[*] Checking common subdomains...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.dns_lookup, self.common_subdomains)

    def check_ssl_certificate(self):
        print("\n[*] Checking SSL certificate...")
        try:
            response = requests.get(f"https://{self.domain}")
            if response.status_code == 200:
                print(f"[+] Found: {self.domain}")
                self.subdomains.add(self.domain)
        except:
            pass

    def find_subdomains(self):
        print(f"\n[*] Starting subdomain enumeration for {self.domain}")
        print("[*] This might take a few minutes...\n")
        start_time = time.time()
        self.check_common_subdomains()
        self.check_ssl_certificate()
        end_time = time.time()
        duration = end_time - start_time
        print(f"\n[*] Subdomain enumeration completed in {duration:.2f} seconds")
        print(f"[*] Found {len(self.subdomains)} subdomains:")
        for subdomain in sorted(self.subdomains):
            print(f"    - {subdomain}")

def check_alive_subdomains(input_file, output_file=None, max_workers=10):
    def is_alive(subdomain):
        urls = [f"http://{subdomain}", f"https://{subdomain}"]
        for url in urls:
            try:
                response = requests.get(url, timeout=3)
                if response.status_code < 400:
                    return subdomain
            except requests.RequestException:
                continue
        return None

    with open(input_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(is_alive, subdomains):
            if result:
                print(f"[ALIVE] {result}")
                alive.append(result)

    if output_file:
        with open(output_file, 'w') as f:
            for sub in alive:
                f.write(sub + '\n')
        print(f"\nAlive subdomains saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Code Vulnerability Scanner and Subdomain Enumerator')
    parser.add_argument('--path', help='Path to the codebase to scan')
    parser.add_argument('--output', help='Output file for the report (HTML format)')
    parser.add_argument('--severity', default='low', choices=['low', 'medium', 'high', 'critical'],
                      help='Minimum severity level to report')
    parser.add_argument('--exclude', nargs='*', default=[],
                      help='Patterns to exclude from scanning')
    parser.add_argument('--max-workers', type=int, default=4,
                      help='Maximum number of worker threads for parallel scanning')
    parser.add_argument('--subdomain', metavar='DOMAIN', help='Enumerate subdomains for the given domain')
    parser.add_argument('--alive-subdomains', metavar='FILE', help='Check which subdomains from file are alive')
    args = parser.parse_args()

    if args.alive_subdomains:
        check_alive_subdomains(args.alive_subdomains, args.output, args.max_workers)
        return

    if args.subdomain:
        finder = SubdomainFinder(args.subdomain)
        finder.find_subdomains()
        return

    if not args.path:
        parser.error('--path is required unless --subdomain or --alive-subdomains is used')

    scanner = VulnerabilityScanner(
        path=args.path,
        output=args.output,
        severity=args.severity,
        exclude=args.exclude,
        max_workers=args.max_workers
    )
    with Console().status("[bold green]Scanning for vulnerabilities..."):
        scanner.scan()
        scanner.generate_report()

if __name__ == "__main__":
    main() 