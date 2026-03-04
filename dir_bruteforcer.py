import requests
import argparse

def brute_force(url, wordlist):
    with open(wordlist, 'r') as file:
        for word in file:
            word = word.strip()
            target = f"{url}/{word}"
            try:
                response = requests.get(target, timeout=3)
                if response.status_code in [200, 301, 302, 403]:
                    print(f"[+] Found: {target} (Status: {response.status_code})")
            except requests.RequestException:
                pass

def main():
    parser = argparse.ArgumentParser(description="Simple Directory Brute Forcer")
    parser.add_argument("url", help="Target URL (e.g. http://192.168.1.10)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    args = parser.parse_args()

    print(f"\nStarting directory brute force on {args.url}\n")
    brute_force(args.url, args.wordlist)
    print("\nScan complete.")

if __name__ == "__main__":
    main()
