import dns.resolver
import argparse
from concurrent.futures import ThreadPoolExecutor

def check_subdomain(domain, sub):
    subdomain = f"{sub}.{domain}"
    try:
        dns.resolver.resolve(subdomain, "A")
        print(f"[+] Found: {subdomain}")
    except:
        pass

def enumerate_subdomains(domain, wordlist):
    with open(wordlist, "r") as f:
        subs = [line.strip() for line in f]

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(lambda sub: check_subdomain(domain, sub), subs)

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("wordlist", help="Wordlist file")

    args = parser.parse_args()

    print(f"\nEnumerating subdomains for {args.domain}\n")
    enumerate_subdomains(args.domain, args.wordlist)

if __name__ == "__main__":
    main()
