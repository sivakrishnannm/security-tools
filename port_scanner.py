import socket
import argparse
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode().strip()
                    if banner:
                        print(f"    Banner: {banner.splitlines()[0]}")
                except:
                    pass
    except:
        pass


def main():
    parser = argparse.ArgumentParser(description="Simple Python Port Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("start_port", type=int, help="Start port")
    parser.add_argument("end_port", type=int, help="End port")
    args = parser.parse_args()

    target = args.target
    start_port = args.start_port
    end_port = args.end_port

    print(f"\nScanning Target: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)

    for port in range(start_port, end_port + 1):
        scan_port(target, port)

    print("-" * 50)
    print(f"Scan completed at: {datetime.now()}")


if __name__ == "__main__":
    main()
