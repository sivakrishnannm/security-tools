# Security Tools

A collection of Python tools built while learning penetration testing and web application security.  
These tools focus on reconnaissance, enumeration, and basic vulnerability detection.

---

## Tools Included

### 1. Port Scanner

A multithreaded TCP port scanner used for identifying open services on a target.

**Features**
- TCP port scanning
- Banner grabbing
- Multithreaded scanning
- Command-line interface using argparse

**Usage**

```bash
python3 port_scanner.py <target> <start_port> <end_port>
```

Example:

```bash
python3 port_scanner.py 192.168.1.10 1 1000
```

---

### 2. Directory Brute Forcer

A web enumeration tool used to discover hidden directories on web servers.

**Features**
- Wordlist-based directory discovery
- Multithreaded scanning
- Custom HTTP headers
- Detects useful responses (200 / 301 / 302 / 403)

**Usage**

```bash
python3 dir_bruteforcer.py <url> <wordlist>
```

Example:

```bash
python3 dir_bruteforcer.py http://example.com /usr/share/wordlists/dirb/common.txt
```

---

### 3. Subdomain Enumerator

A DNS-based subdomain discovery tool used during reconnaissance.

**Features**
- Wordlist-based subdomain discovery
- DNS resolution using dnspython
- Multithreaded scanning

**Usage**

```bash
python3 subdomain_enum.py <domain> <wordlist>
```

Example:

```bash
python3 subdomain_enum.py example.com subdomains.txt
```

---

### 4. Mini Web Vulnerability Scanner

A Python-based scanner that performs basic reconnaissance and vulnerability checks on web applications.

**Features**
- Common port scanning
- Security header analysis
- Technology fingerprinting
- HTML technology detection
- Directory discovery
- robots.txt parsing
- TLS certificate inspection
- Subdomain enumeration
- Basic XSS reflection testing
- HTTP method enumeration
- GET parameter discovery
- Generates TXT and JSON reports

**Usage**

```bash
python3 mini_vuln_scanner.py http://example.com
```

Optional flags:

```bash
--wordlist <file>
--threads <number>
--delay <seconds>
--no-tls
--no-xss
--no-methods
--no-params
```

---

## Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

Required libraries:

- requests
- dnspython
- tldextract
- colorama

---

## Purpose

These tools were built as part of my journey into cybersecurity and penetration testing.  
They help demonstrate practical understanding of reconnaissance, enumeration, and vulnerability assessment concepts.

---

## Disclaimer

These tools are intended **for educational purposes and authorized security testing only**.  
Do not use them against systems without permission.
