import socket
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        s.close()
    except:
        pass

def main():
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <target> <start_port> <end_port>")
        sys.exit()

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"\nScanning Target: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)

    for port in range(start_port, end_port + 1):
        scan_port(target, port)

    print("-" * 50)
    print(f"Scan completed at: {datetime.now()}")

if __name__ == "__main__":
    main()
