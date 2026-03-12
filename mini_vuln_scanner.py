#!/usr/bin/env python3
"""
Mini Web Vulnerability Scanner  v5.0
--------------------------------------
Scans a target URL for:
  - Open common ports
  - Missing security headers  +  technology fingerprinting
  - HTML-based technology detection  (WordPress, React, Drupal, etc.)
  - Common directory exposure  (with response size, title, redirect chain)
  - robots.txt parsing  (hidden paths)
  - TLS / HTTPS certificate info  (issuer, expiry, version)
  - Subdomains via DNS
  - Basic XSS reflection test
  - HTTP method enumeration  (PUT, DELETE, TRACE, OPTIONS)
  - GET parameter discovery  (?id=, ?file=, ?page=, ...)
  - Rate limiting  +  configurable threads via CLI flags
  - Progress indicator during directory scan  [N/total]
  - Target reachability check before scanning
  - Saves report to  .txt  and  .json

Usage:
  scanner.py <url>
  scanner.py <url> --wordlist wordlist.txt
  scanner.py <url> --delay 0.2 --threads 30
  scanner.py <url> --no-tls --no-xss
"""

import socket
import ssl
import sys
import json
import time
import threading
import datetime
import argparse
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)   # reset color after every print automatically
    COLOR = True
except ImportError:
    COLOR = False

import re

# ── Color helpers ─────────────────────────────────────────────────────────────
# All output goes through these four functions so color is always consistent
# and can be stripped in one place (just set COLOR = False).

def _c(text: str, *codes) -> str:
    """Wrap text in ANSI codes if colorama is available."""
    if not COLOR:
        return text
    return "".join(codes) + text + Style.RESET_ALL


def good(text: str)  -> str: return _c(text, Fore.GREEN)   # [+]
def warn(text: str)  -> str: return _c(text, Fore.YELLOW)  # [~]
def bad(text: str)   -> str: return _c(text, Fore.RED)     # [!]
def info(text: str)  -> str: return _c(text, Fore.CYAN)    # [*]
def dim(text: str)   -> str: return _c(text, Fore.WHITE)   # neutral

# ── Config ────────────────────────────────────────────────────────────────────

HEADERS = {"User-Agent": "Mozilla/5.0 MiniScanner/5.0"}

def make_session() -> requests.Session:
    """Return a shared Session with default headers (connection reuse, faster scanning)."""
    s = requests.Session()
    s.headers.update(HEADERS)
    return s

# One global session — reused across all HTTP calls
SESSION = make_session()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

COMMON_DIRS = [
    "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/uploads", "/backup", "/config", "/test",
    "/api", "/api/v1", "/api/v2", "/.git", "/.env", "/robots.txt",
    "/sitemap.xml", "/server-status", "/dashboard", "/panel",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SUBDOMAINS = [
    "www", "mail", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "ftp", "app", "blog", "shop", "static",
]

XSS_PAYLOAD = "<script>alert(1)</script>"

TIMEOUT    = 4    # seconds per request
RATE_DELAY = 0.1  # seconds between directory probe requests (0 to disable)
THREADS    = 15   # worker threads for directory + subdomain scans

# ── Helpers ───────────────────────────────────────────────────────────────────

def banner():
    line = "╔══════════════════════════════════════════════╗\n" \
           "║     Mini Web Vulnerability Scanner  v5.0   ║\n" \
           "╚══════════════════════════════════════════════╝"
    print(_c(line, Fore.CYAN if COLOR else "") if COLOR else line)
    print()


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_host(url: str) -> str:
    return urlparse(url).hostname


def get_base_domain(host: str) -> str:
    """Return the registrable domain, handling ccTLDs like .co.uk correctly."""
    if TLD_AVAILABLE:
        extracted = tldextract.extract(host)
        return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else host
    # Fallback: naive last-two-parts (works for simple TLDs)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ── 1. Reachability Check ─────────────────────────────────────────────────────

def check_reachability(url: str) -> bool:
    """Quick HEAD/GET to confirm the target is up before running the full scan."""
    print(info(f"[*] Checking target reachability ...\n"))
    try:
        r = SESSION.get(url, timeout=5, allow_redirects=True)
        print(good(f"  [+] Target is UP  (HTTP {r.status_code})\n"))
        return True
    except requests.ConnectionError:
        print(bad(f"  [!] Target is DOWN or unreachable — aborting.\n"))
        return False
    except requests.Timeout:
        print(bad(f"  [!] Target timed out — aborting.\n"))
        return False
    except requests.RequestException as e:
        print(bad(f"  [!] Unexpected error: {e} — aborting.\n"))
        return False


# ── 2. Port Scanner ───────────────────────────────────────────────────────────

def scan_port(host: str, port: int) -> tuple[int, bool]:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def scan_ports(url: str) -> list[int]:
    host = get_host(url)
    print(info(f"\n[*] Scanning ports on {host} ...\n"))
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as ex:  # ports are fast — high concurrency helps
        futures = {ex.submit(scan_port, host, p): p for p in COMMON_PORTS}
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                print(good(f"  [+] Port {port} open"))
                open_ports.append(port)

    if not open_ports:
        print(dim("  [-] No common ports found open"))
    return sorted(open_ports)


# ── 2. TLS / HTTPS Certificate Info ──────────────────────────────────────────

def check_tls(url: str) -> dict:
    """
    Connect via SSL and extract:
      - TLS version negotiated
      - Certificate issuer (CN / O)
      - Subject (domain)
      - Expiry date  +  days remaining
      - Self-signed warning
    Returns an empty dict if the target is HTTP-only or port 443 is closed.
    """
    host = get_host(url)
    tls_data: dict = {}

    print(info(f"\n[*] Checking TLS certificate ...\n"))

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                tls_ver   = ssock.version()
                cert      = ssock.getpeercert()
                subject   = dict(x[0] for x in cert.get("subject", []))
                issuer    = dict(x[0] for x in cert.get("issuer",  []))
                not_after = cert.get("notAfter", "")
                expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") \
                            if not_after else None
                days_left = (expiry_dt - datetime.datetime.utcnow()).days \
                            if expiry_dt else None

                tls_data = {
                    "tls_version": tls_ver,
                    "subject_cn":  subject.get("commonName", "?"),
                    "issuer_org":  issuer.get("organizationName",
                                   issuer.get("commonName", "?")),
                    "expiry":      not_after,
                    "days_left":   days_left,
                    "self_signed": subject == issuer,
                }

                print(good(f"  [+] TLS version  : {tls_ver}"))
                print(good(f"  [+] Subject CN   : {tls_data['subject_cn']}"))
                print(good(f"  [+] Issuer       : {tls_data['issuer_org']}"))
                print(good(f"  [+] Expires      : {not_after}"))
                if days_left is not None:
                    if days_left < 0:
                        print(bad(f"  [!] CERTIFICATE EXPIRED  ({abs(days_left)} days ago)"))
                    elif days_left < 30:
                        print(bad(f"  [!] Expiring soon        ({days_left} days left)"))
                    else:
                        print(good(f"  [+] Days remaining       : {days_left}"))
                if tls_data["self_signed"]:
                    print(bad(f"  [!] Self-signed certificate detected"))

    except ssl.SSLCertVerificationError as e:
        print(bad(f"  [!] SSL verification error: {e}"))
        tls_data = {"error": str(e)}
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(dim(f"  [-] Port 443 not reachable — skipping TLS check"))

    return tls_data


# ── 3. Security Headers  +  Technology Fingerprinting ────────────────────────

def check_security_headers(url: str) -> tuple[list, list, dict]:
    print(info(f"\n[*] Checking security headers ...\n"))
    missing, present = [], []
    tech: dict = {}

    try:
        r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)

        for header in SECURITY_HEADERS:
            if header in r.headers:
                print(good(f"  [+] {header}: present"))
                present.append(header)
            else:
                print(bad(f"  [!] Missing: {header}"))
                missing.append(header)

        print(info(f"\n[*] Detecting technologies ...\n"))

        fingerprints = [
            ("Server",          "Server"),
            ("X-Powered-By",    "X-Powered-By"),
            ("X-AspNet-Version","ASP.NET"),
            ("X-Generator",     "Generator"),
        ]
        detected_any = False
        for http_hdr, label in fingerprints:
            val = r.headers.get(http_hdr)
            if val:
                print(good(f"  [+] {label:<18} {val}"))
                tech[label] = val
                detected_any = True

        set_cookie = r.headers.get("Set-Cookie", "")
        if set_cookie:
            bad_flags = [f for f in ("HttpOnly", "Secure", "SameSite")
                         if f not in set_cookie]
            if bad_flags:
                issues = ", ".join(f"missing {f}" for f in bad_flags)
                print(warn(f"  [~] Cookie issues:  {issues}"))
                tech["Cookie-Issues"] = bad_flags
                detected_any = True

        if not detected_any:
            print(dim("  [-] No technology headers detected"))

    except requests.RequestException as e:
        print(bad(f"  [ERROR] Could not connect: {e}"))
        return [], [], {}

    return present, missing, tech


# ── 4. HTML Technology Detection ─────────────────────────────────────────────

# Each entry: (display_name, list_of_patterns_to_search_in_HTML)
HTML_TECH_SIGNATURES: list[tuple[str, list[str]]] = [
    ("WordPress",       ["wp-content/", "wp-includes/", "xmlrpc.php"]),
    ("Drupal",          ["Drupal.settings", "/sites/default/files/", "drupal.js"]),
    ("Joomla",          ["/media/jui/", "Joomla!", "/components/com_"]),
    ("React",           ["react.development.js", "react.production.min.js",
                         "__REACT_DEVTOOLS", "data-reactroot", "data-reactid"]),
    ("Next.js",         ["__NEXT_DATA__", "_next/static/", "next/dist"]),
    ("Angular",         ["ng-version=", "angular.min.js", "ng-app", "@angular"]),
    ("Vue.js",          ["vue.min.js", "vue.runtime", "__vue__", "data-v-"]),
    ("jQuery",          ["jquery.min.js", "jquery.js", "jQuery v"]),
    ("Bootstrap",       ["bootstrap.min.css", "bootstrap.min.js", "bootstrap.css"]),
    ("Tailwind CSS",    ["tailwindcss", "tw-", "tailwind.config"]),
    ("Laravel",         ["laravel_session", "XSRF-TOKEN", "laravel"]),
    ("Django",          ["csrfmiddlewaretoken", "django", "__django_"]),
    ("ASP.NET",         ["__VIEWSTATE", "__EVENTTARGET", "asp.net"]),
    ("Google Analytics",["google-analytics.com/analytics.js", "gtag(", "ga("]),
    ("Cloudflare",      ["cdn-cgi/", "__cf_bm", "cloudflare"]),
]

def detect_html_technologies(url: str) -> list[str]:
    """Fetch homepage HTML and scan for known framework/library fingerprints."""
    print(info(f"\n[*] Detecting technologies from HTML ...\n"))
    detected = []

    try:
        r = SESSION.get(url, timeout=TIMEOUT, allow_redirects=True)
        html = r.text[:500_000]   # cap at 500 KB — avoids hanging on huge pages

        for tech_name, patterns in HTML_TECH_SIGNATURES:
            if any(pat.lower() in html.lower() for pat in patterns):
                print(good(f"  [+] Detected: {tech_name}"))
                detected.append(tech_name)

        if not detected:
            print(dim("  [-] No known frameworks/libraries detected in HTML"))

    except requests.RequestException as e:
        print(bad(f"  [ERROR] Could not fetch page HTML: {e}"))

    return detected


# ── 5. Directory Discovery ────────────────────────────────────────────────────

def extract_title(html: bytes) -> str | None:
    """Pull <title>...</title> from raw HTML bytes, return None if absent."""
    match = re.search(rb"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).decode("utf-8", errors="replace").strip()
        return title[:80] if title else None
    return None


def probe_dir(url: str, path: str,
              counter: list, lock: threading.Lock, total: int) -> dict:
    """
    Probe a single path with:
      - rate limiting  (RATE_DELAY sleep before each request)
      - thread-safe progress indicator  [N/total]
    Returns a dict: path, code, size, title, redirect_to
    """
    # Rate limit — sleep before firing the request
    if RATE_DELAY > 0:
        time.sleep(RATE_DELAY)

    # Update + print progress (thread-safe)
    with lock:
        counter[0] += 1
        n = counter[0]
    # \r overwrites the same line; flush ensures it appears immediately
    print(f"  [{n:>{len(str(total))}}/{total}] Testing {path:<32}", end="\r", flush=True)

    result = {"path": path, "code": None, "size": 0,
              "title": None, "redirect_to": None}
    try:
        r = SESSION.get(url + path, timeout=TIMEOUT, allow_redirects=False)
        result["code"] = r.status_code
        result["size"] = len(r.content)

        if r.status_code in (301, 302, 303, 307, 308):
            result["redirect_to"] = r.headers.get("Location", "?")
        elif r.status_code == 200:
            result["title"] = extract_title(r.content)

    except requests.RequestException:
        pass
    return result


def load_wordlist(path: str) -> list[str]:
    """Read a wordlist file, one path per line. Lines not starting with / get one prepended."""
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return [p if p.startswith("/") else "/" + p for p in lines]
    except FileNotFoundError:
        print(f"  [ERROR] Wordlist not found: {path}")
        return COMMON_DIRS


def scan_directories(url: str, wordlist_path: str | None = None) -> list[dict]:
    dirs = load_wordlist(wordlist_path) if wordlist_path else COMMON_DIRS
    total  = len(dirs)
    source = f"wordlist ({wordlist_path})" if wordlist_path else "built-in list"
    print(info(f"\n[*] Scanning {total} directories  [{source}] ...\n"))

    found   = []
    counter = [0]
    lock    = threading.Lock()

    STATUS_LABEL = {200: "OK", 301: "Moved", 302: "Found",
                    303: "See Other", 307: "Temp Redirect",
                    308: "Perm Redirect", 403: "Forbidden"}

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {
            ex.submit(probe_dir, url, d, counter, lock, total): d
            for d in dirs
        }
        for fut in as_completed(futures):
            res  = fut.result()
            code = res["code"]
            if code is None:
                continue

            label = STATUS_LABEL.get(code, str(code))
            path  = res["path"]
            size  = res["size"]

            if code < 400:
                print(" " * 60, end="\r")
                line = f"  [+] {path:<32} ({code} {label}) [{size} bytes]"
                if res["redirect_to"]:
                    line += f"\n       └─ → {res['redirect_to']}"
                elif res["title"]:
                    line += f'\n       └─ title: "{res["title"]}"'
                print(good(line))
                found.append(res)
            elif code == 403:
                print(" " * 60, end="\r")
                print(warn(f"  [~] {path:<32} (403 Forbidden) [{size} bytes]"))
                found.append(res)

    print(" " * 60, end="\r")
    if not found:
        print(dim("  [-] No interesting directories found"))
    return found


# ── 6. robots.txt Parser ─────────────────────────────────────────────────────

def parse_robots(url: str) -> list[str]:
    """Fetch /robots.txt and extract all Disallow paths — a goldmine for recon."""
    print(info(f"\n[*] Parsing robots.txt ...\n"))
    paths = []

    try:
        r = SESSION.get(url + "/robots.txt", timeout=TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            print(dim(f"  [-] robots.txt not found ({r.status_code})"))
            return []

        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    print(good(f"  [+] Disallow: {path}"))
                    paths.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                print(warn(f"  [~] Sitemap:  {sitemap}"))

        if not paths:
            print(dim("  [-] No interesting Disallow entries found"))

    except requests.RequestException as e:
        print(bad(f"  [ERROR] Could not fetch robots.txt: {e}"))

    return paths


# ── 7. Subdomain Scanner ──────────────────────────────────────────────────────

def probe_subdomain(base_domain: str, sub: str) -> tuple[str, str | None]:
    fqdn = f"{sub}.{base_domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3   # total seconds before giving up — prevents hangs
        answers = resolver.resolve(fqdn, "A")
        return fqdn, str(answers[0])
    except Exception:
        return fqdn, None


def scan_subdomains(url: str) -> list[tuple]:
    if not DNS_AVAILABLE:
        print(warn("\n[*] Subdomain scan skipped — install dnspython:  pip install dnspython\n"))
        return []

    host = get_host(url)
    base = get_base_domain(host)
    print(info(f"\n[*] Scanning subdomains of {base} ...\n"))
    found = []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(probe_subdomain, base, s): s for s in SUBDOMAINS}
        for fut in as_completed(futures):
            fqdn, ip = fut.result()
            if ip:
                print(good(f"  [+] {fqdn:<38} → {ip}"))
                found.append((fqdn, ip))

    if not found:
        print(dim("  [-] No subdomains resolved"))
    return found


# ── 8. Basic XSS Reflection Test ─────────────────────────────────────────────

def test_xss(url: str) -> list[str]:
    print(info(f"\n[*] Testing basic XSS reflection ...\n"))
    vulnerable = []
    test_params = ["q", "search", "query", "s", "id", "input", "term"]

    for param in test_params:
        test_url = f"{url}?{param}={XSS_PAYLOAD}"
        try:
            r = SESSION.get(test_url, timeout=TIMEOUT, allow_redirects=True)
            if XSS_PAYLOAD in r.text:
                print(bad(f"  [!] XSS reflected via ?{param}="))
                vulnerable.append(param)
            else:
                print(good(f"  [+] ?{param}= — not reflected"))
        except requests.RequestException:
            print(dim(f"  [-] ?{param}= — request failed"))

    if not vulnerable:
        print(good("\n  [✓] No XSS reflection detected in tested params"))
    return vulnerable


# ── 9. HTTP Method Enumeration ────────────────────────────────────────────────

# Methods that are safe to probe but dangerous when enabled
RISKY_METHODS = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]

def test_http_methods(url: str) -> list[str]:
    """
    Send each risky HTTP method to the root path and flag anything that
    gets a non-405 / non-501 response (i.e. the server didn't reject it).
    OPTIONS is also parsed for its Allow header.
    """
    print(info(f"\n[*] Testing HTTP methods ...\n"))
    risky_enabled = []

    for method in RISKY_METHODS:
        try:
            r = SESSION.request(method, url, timeout=TIMEOUT, allow_redirects=False)
            code = r.status_code

            if method == "OPTIONS":
                allow = r.headers.get("Allow", "")
                if allow:
                    # OPTIONS itself is normal — just report what's advertised
                    print(info(f"  [*] Allow header: {allow}"))
                    # Only flag genuinely dangerous methods listed in Allow
                    dangerous = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in allow]
                    for m in dangerous:
                        print(bad(f"  [!] {m:<8} — listed in Allow header"))
                        risky_enabled.append(f"{m} (via OPTIONS Allow header)")
                    if not dangerous:
                        print(good(f"  [+] OPTIONS — no dangerous methods in Allow header"))
                else:
                    print(good(f"  [+] OPTIONS — no Allow header returned"))
            elif code in (405, 501):
                print(good(f"  [+] {method:<8} — disabled ({code})"))
            elif code == 200:
                print(bad(f"  [!] {method:<8} — ENABLED (200 OK)"))
                risky_enabled.append(method)
            else:
                print(warn(f"  [~] {method:<8} — unexpected response ({code})"))
                risky_enabled.append(f"{method} ({code})")

        except requests.RequestException:
            print(dim(f"  [-] {method:<8} — request failed"))

    if not risky_enabled:
        print(good("\n  [✓] No risky HTTP methods detected"))
    return risky_enabled


# ── 10. GET Parameter Discovery ───────────────────────────────────────────────

COMMON_PARAMS = [
    "id", "page", "file", "view", "path", "url", "name",
    "query", "search", "q", "cat", "dir", "action", "type",
    "lang", "ref", "redirect", "next", "token", "user",
]

# Canary value — something distinctive that won't appear naturally in any page
PARAM_CANARY = "MVSCAN_PROBE_7749"

def _probe_param(url: str, param: str) -> tuple[str, bool]:
    """Probe a single GET parameter. Returns (param, reflected)."""
    try:
        r = SESSION.get(f"{url}?{param}={PARAM_CANARY}", timeout=TIMEOUT,
                        allow_redirects=True)
        return param, PARAM_CANARY in r.text
    except requests.RequestException:
        return param, False


def discover_params(url: str) -> list[str]:
    """
    Test each common parameter by appending it with a canary value.
    Runs in parallel for a ~5x speed improvement over sequential probing.
    A parameter is considered 'reflected' if the canary appears in the response —
    worth investigating further for injection or path traversal.
    """
    print(info(f"\n[*] Discovering GET parameters ...\n"))
    reflected = []

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(_probe_param, url, p): p for p in COMMON_PARAMS}
        for fut in as_completed(futures):
            param, is_reflected = fut.result()
            if is_reflected:
                print(warn(f"  [~] ?{param}= — value reflected in response"))
                reflected.append(param)
            else:
                print(good(f"  [+] ?{param}= — not reflected"))

    if not reflected:
        print(good("\n  [✓] No reflected parameters found"))
    return reflected


# ── 11. Vulnerability Summary ─────────────────────────────────────────────────

def build_summary(open_ports, missing_headers, found_dirs, robots_paths,
                  xss_params, http_methods, reflected_params,
                  tech, html_tech, tls_info) -> list[str]:
    vulns = []

    DANGER_PORTS = {
        21:   "FTP open — may allow anonymous login",
        23:   "Telnet open — unencrypted remote access",
        25:   "SMTP open — may be used for spam relay",
        445:  "SMB open — vulnerable to ransomware attacks",
        3306: "MySQL exposed — database publicly reachable",
        3389: "RDP exposed — remote desktop publicly reachable",
    }
    for port, msg in DANGER_PORTS.items():
        if port in open_ports:
            vulns.append(f"Port {port}: {msg}")

    if missing_headers:
        vulns.append(
            f"Missing {len(missing_headers)} security header(s): "
            f"{', '.join(missing_headers)}"
        )

    SENSITIVE_PATHS = {"/.git", "/.env", "/backup", "/config",
                       "/phpmyadmin", "/server-status"}
    EXPOSED_DIRS    = {"/uploads", "/admin", "/administrator"}
    for res in found_dirs:
        path, code, size = res["path"], res["code"], res["size"]
        if path in SENSITIVE_PATHS and code == 200:
            vulns.append(f"Sensitive path accessible: {path} ({size} bytes)")
        elif path in EXPOSED_DIRS and code == 200:
            vulns.append(f"Exposed directory: {path} ({size} bytes)")

    # robots.txt hidden paths worth noting
    interesting_robots = [p for p in robots_paths
                          if any(kw in p.lower() for kw in
                                 ("admin", "internal", "private", "secret",
                                  "backup", "config", "api", "dev"))]
    for p in interesting_robots:
        vulns.append(f"Interesting robots.txt Disallow path: {p}")

    for param in xss_params:
        vulns.append(f"XSS reflected via GET param: ?{param}=")

    for method in http_methods:
        vulns.append(f"Risky HTTP method enabled: {method}")

    if reflected_params:
        vulns.append(
            f"GET params reflected (investigate for injection): "
            f"{', '.join('?' + p + '=' for p in reflected_params)}"
        )

    powered_by = tech.get("X-Powered-By", "")
    if any(v in powered_by for v in ("PHP/4", "PHP/5")):
        vulns.append(f"Outdated PHP detected: {powered_by}")

    if "Cookie-Issues" in tech:
        vulns.append(f"Cookie security flags: {', '.join(tech['Cookie-Issues'])}")

    # TLS issues
    if tls_info:
        if tls_info.get("self_signed"):
            vulns.append("Self-signed TLS certificate detected")
        days = tls_info.get("days_left")
        if days is not None and days < 0:
            vulns.append(f"TLS certificate EXPIRED ({abs(days)} days ago)")
        elif days is not None and days < 30:
            vulns.append(f"TLS certificate expiring in {days} days")
        tls_ver = tls_info.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            vulns.append(f"Outdated TLS version in use: {tls_ver}")

    return vulns


def print_summary(vulns: list[str]):
    print("\n" + _c("═" * 50, Fore.CYAN if COLOR else ""))
    print(_c("  VULNERABILITY SUMMARY", Fore.CYAN if COLOR else ""))
    print(_c("═" * 50, Fore.CYAN if COLOR else "") + "\n")
    if vulns:
        for v in vulns:
            print(bad(f"  [!] {v}"))
    else:
        print(good("  [✓] No obvious vulnerabilities detected"))
    print()


# ── 12. Report Export ─────────────────────────────────────────────────────────

def save_report(url, open_ports, present_hdrs, missing_hdrs, tech, html_tech,
                tls_info, found_dirs, robots_paths, subdomains,
                xss_params, http_methods, reflected_params, vulns):

    ts        = datetime.datetime.now()
    host      = get_host(url)
    base_name = f"scan_{host}_{ts.strftime('%Y%m%d_%H%M%S')}"

    # ── TXT ───────────────────────────────────────────────────────────────────
    txt_path = f"{base_name}.txt"
    sep = "─" * 50

    with open(txt_path, "w") as f:
        def w(line=""):
            f.write(line + "\n")

        w("Mini Web Vulnerability Scanner v5.0")
        w(f"Scan date : {ts.isoformat()}")
        w(f"Target    : {url}")
        w("=" * 50)

        w("\nOPEN PORTS")
        w(sep)
        w("\n".join(f"  [+] Port {p}" for p in open_ports) or "  [-] None found")

        w("\nTLS CERTIFICATE")
        w(sep)
        if tls_info and "error" not in tls_info:
            w(f"  TLS version  : {tls_info.get('tls_version', '?')}")
            w(f"  Subject CN   : {tls_info.get('subject_cn', '?')}")
            w(f"  Issuer       : {tls_info.get('issuer_org', '?')}")
            w(f"  Expires      : {tls_info.get('expiry', '?')}")
            w(f"  Days left    : {tls_info.get('days_left', '?')}")
            w(f"  Self-signed  : {tls_info.get('self_signed', False)}")
        else:
            w("  [-] No TLS info available")

        w("\nSECURITY HEADERS")
        w(sep)
        w("\n".join(f"  [+] {h}: present" for h in present_hdrs))
        w("\n".join(f"  [!] Missing: {h}" for h in missing_hdrs))

        w("\nTECHNOLOGY FINGERPRINT (headers)")
        w(sep)
        w("\n".join(f"  {k}: {v}" for k, v in tech.items()) or "  None detected")

        w("\nTECHNOLOGY DETECTION (HTML)")
        w(sep)
        w("\n".join(f"  [+] {t}" for t in html_tech) or "  None detected")

        w("\nDIRECTORIES")
        w(sep)
        if found_dirs:
            for res in found_dirs:
                line = f"  [+] {res['path']} ({res['code']}) [{res['size']} bytes]"
                if res.get("redirect_to"):
                    line += f"  → {res['redirect_to']}"
                elif res.get("title"):
                    line += f'  title: "{res["title"]}"'
                w(line)
        else:
            w("  [-] None found")

        w("\nROBOTS.TXT PATHS")
        w(sep)
        w("\n".join(f"  Disallow: {p}" for p in robots_paths) or "  [-] None found")

        w("\nSUBDOMAINS")
        w(sep)
        w("\n".join(f"  [+] {d} → {ip}"
                    for d, ip in subdomains) or "  [-] None found")

        w("\nXSS REFLECTION")
        w(sep)
        w("\n".join(f"  [!] ?{p}= reflected"
                    for p in xss_params) or "  [✓] None detected")

        w("\nHTTP METHODS")
        w(sep)
        w("\n".join(f"  [!] Risky method: {m}" for m in http_methods) or "  [✓] None detected")

        w("\nPARAMETER DISCOVERY")
        w(sep)
        w("\n".join(f"  [~] ?{p}= reflected" for p in reflected_params) or "  [-] None found")

        w("\nVULNERABILITIES")
        w(sep)
        w("\n".join(f"  [!] {v}" for v in vulns) or "  [✓] None detected")

    print(f"  [✓] TXT  saved → {txt_path}")

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = f"{base_name}.json"
    report = {
        "scanner":    "Mini Web Vulnerability Scanner v5.0",
        "timestamp":  ts.isoformat(),
        "target":     url,
        "open_ports": open_ports,
        "tls":        tls_info,
        "security_headers": {
            "present": present_hdrs,
            "missing": missing_hdrs,
        },
        "technologies_headers":  tech,
        "technologies_html":     html_tech,
        "directories":           found_dirs,
        "robots_paths":          robots_paths,
        "subdomains":            [{"fqdn": d, "ip": ip} for d, ip in subdomains],
        "xss_reflected_params":  xss_params,
        "http_methods_enabled":  http_methods,
        "reflected_params":      reflected_params,
        "vulnerabilities":       vulns,
    }
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  [✓] JSON saved → {json_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mini_vuln_scanner.py",
        description="Mini Web Vulnerability Scanner v5.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python scanner.py http://example.com
  python scanner.py http://example.com --wordlist dirs.txt
  python scanner.py http://example.com --delay 0.2 --threads 30
  python scanner.py http://example.com --no-tls --no-xss --no-params
""",
    )
    p.add_argument("url",            nargs="?",           help="Target URL (prompted if omitted)")
    p.add_argument("--wordlist",     metavar="FILE",      help="Path to directory wordlist")
    p.add_argument("--delay",        type=float,          default=0.1,  metavar="SEC",
                   help="Delay between dir requests in seconds (default: 0.1)")
    p.add_argument("--threads",      type=int,            default=15,   metavar="N",
                   help="Worker threads for dir/subdomain scans (default: 15)")
    p.add_argument("--no-tls",       action="store_true", help="Skip TLS certificate check")
    p.add_argument("--no-subdomains",action="store_true", help="Skip subdomain scan")
    p.add_argument("--no-xss",       action="store_true", help="Skip XSS reflection test")
    p.add_argument("--no-methods",   action="store_true", help="Skip HTTP method enumeration")
    p.add_argument("--no-params",    action="store_true", help="Skip GET parameter discovery")
    return p.parse_args()


def main():
    global RATE_DELAY, THREADS
    banner()
    args = parse_args()

    target = args.url or input("Enter target URL (e.g. http://example.com): ").strip()
    if not target:
        print(bad("No target provided. Exiting."))
        sys.exit(1)

    # Apply CLI overrides to module-level config
    RATE_DELAY = args.delay
    THREADS    = args.threads

    url = normalize_url(target)
    print(info(f"  Target    : {url}"))
    print(info(f"  Host      : {get_host(url)}"))
    if args.wordlist:
        print(info(f"  Wordlist  : {args.wordlist}"))
    print(info(f"  Threads   : {THREADS}   Delay: {RATE_DELAY}s"))
    print(info(f"  Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print("  " + "─" * 44)

    # ── Reachability gate ─────────────────────────────────────────────────────
    if not check_reachability(url):
        sys.exit(1)

    # ── Scan modules ──────────────────────────────────────────────────────────
    open_ports                       = scan_ports(url)
    tls_info                         = check_tls(url)        if not args.no_tls        else {}
    present_hdrs, missing_hdrs, tech = check_security_headers(url)
    html_tech                        = detect_html_technologies(url)
    found_dirs                       = scan_directories(url, args.wordlist)
    robots_paths                     = parse_robots(url)
    subdomains                       = scan_subdomains(url)  if not args.no_subdomains  else []
    xss_params                       = test_xss(url)         if not args.no_xss         else []
    http_methods                     = test_http_methods(url) if not args.no_methods    else []
    reflected_params                 = discover_params(url)  if not args.no_params      else []

    vulns = build_summary(open_ports, missing_hdrs, found_dirs, robots_paths,
                          xss_params, http_methods, reflected_params,
                          tech, html_tech, tls_info)
    print_summary(vulns)

    print(info("[*] Saving reports ...\n"))
    save_report(url, open_ports, present_hdrs, missing_hdrs, tech, html_tech,
                tls_info, found_dirs, robots_paths, subdomains,
                xss_params, http_methods, reflected_params, vulns)
    print()


if __name__ == "__main__":
    main()
