import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

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

def main():
    parser = argparse.ArgumentParser(description="Check which subdomains are alive.")
    parser.add_argument('--input', required=True, help='File containing subdomains (one per line)')
    parser.add_argument('--output', help='File to save alive subdomains (optional)')
    parser.add_argument('--max-workers', type=int, default=10, help='Number of threads to use')
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]

    alive = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        for result in executor.map(is_alive, subdomains):
            if result:
                print(f"[ALIVE] {result}")
                alive.append(result)

    if args.output:
        with open(args.output, 'w') as f:
            for sub in alive:
                f.write(sub + '\n')
        print(f"\nAlive subdomains saved to {args.output}")

if __name__ == "__main__":
    main() 