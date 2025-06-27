import dns.resolver
import socket
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import  burlparse
import sys
import time

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
        """Perform DNS lookup for a subdomain"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            for answer in answers:
                self.subdomains.add(full_domain)
                print(f"[+] Found: {full_domain} -> {answer}")
        except:
            pass

    def check_common_subdomains(self):
        """Check for common subdomains"""
        print("\n[*] Checking common subdomains...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.dns_lookup, self.common_subdomains)

    def check_ssl_certificate(self):
        """Check SSL certificate for additional subdomains"""
        print("\n[*] Checking SSL certificate...")
        try:
            response = requests.get(f"https://{self.domain}")
            if response.status_code == 200:
                print(f"[+] Found: {self.domain}")
                self.subdomains.add(self.domain)
        except:
            pass

    def find_subdomains(self):
        """Main method to find subdomains"""
        print(f"\n[*] Starting subdomain enumeration for {self.domain}")
        print("[*] This might take a few minutes...\n")

        start_time = time.time()
        
        # Check common subdomains
        self.check_common_subdomains()
        
        # Check SSL certificate
        self.check_ssl_certificate()

        end_time = time.time()
        duration = end_time - start_time

        print(f"\n[*] Subdomain enumeration completed in {duration:.2f} seconds")
        print(f"[*] Found {len(self.subdomains)} subdomains:")
        for subdomain in sorted(self.subdomains):
            print(f"    - {subdomain}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python subdomain_finder.py <domain>")
        print("Example: python subdomain_finder.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    finder = SubdomainFinder(domain)
    finder.find_subdomains()

if __name__ == "__main__":
    main() 