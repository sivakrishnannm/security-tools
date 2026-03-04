import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

def check_directory(url, word):
    target = f"{url}/{word}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(target, headers=headers, timeout=3)

        if response.status_code in [200, 301, 302, 403]:
            print(f"[+] Found: {target} (Status: {response.status_code})")

    except requests.RequestException:
        pass


def brute_force(url, wordlist):
    with open(wordlist, "r") as file:
        words = [line.strip() for line in file]

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(lambda word: check_directory(url, word), words)


def main():
    parser = argparse.ArgumentParser(description="Directory Brute Forcer")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("wordlist", help="Path to wordlist")

    args = parser.parse_args()

    print(f"\nStarting scan on {args.url}")
    print("-" * 40)

    brute_force(args.url, args.wordlist)

    print("\nScan complete.")


if __name__ == "__main__":
    main()
