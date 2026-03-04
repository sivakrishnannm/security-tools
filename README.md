# Security Tools

A collection of Python tools built while learning penetration testing.

## Tools Included

### 1. Port Scanner
Features:
- TCP port scanning
- Banner grabbing
- Multithreaded scanning
- Command line interface using argparse

Usage:
python3 port_scanner.py <target> <start_port> <end_port>

Example:
python3 port_scanner.py 192.168.1.10 1 1000


### 2. Directory Brute Forcer
Features:
- Wordlist-based directory discovery
- Multithreaded scanning
- Custom HTTP headers
- Detects 200 / 301 / 302 / 403 responses

Usage:
python3 dir_bruteforcer.py <url> <wordlist>

Example:
python3 dir_bruteforcer.py http://192.168.1.10 /usr/share/wordlists/dirb/common.txt


## Purpose

These tools were built as part of my journey into penetration testing and security automation.
