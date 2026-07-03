"""
Module 1: Multi-threaded Port Scanner
"""

import socket
import threading
from datetime import datetime
from queue import Queue

print_lock = threading.Lock()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}


def scan_port(target, port, open_ports, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            with print_lock:
                print(f"[OPEN] Port {port:<6} -> {service}")
                open_ports.append((port, service))
        sock.close()
    except socket.error:
        pass


def worker(target, q, open_ports):
    while not q.empty():
        port = q.get()
        scan_port(target, port, open_ports)
        q.task_done()


def run():
    print("\n=== PORT SCANNER ===")
    target = input("Target IP/hostname: ").strip()
    start_port = input("Start port [default 1]: ").strip()
    end_port = input("End port [default 1024]: ").strip()
    start_port = int(start_port) if start_port else 1
    end_port = int(end_port) if end_port else 1024

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Hostname tidak bisa di-resolve.")
        return

    print("=" * 50)
    print(f"Scanning target: {target} ({target_ip})")
    print(f"Port range     : {start_port}-{end_port}")
    print(f"Started at     : {datetime.now()}")
    print("=" * 50)

    open_ports = []
    q = Queue()
    for port in range(start_port, end_port + 1):
        q.put(port)

    threads = []
    for _ in range(100):
        t = threading.Thread(target=worker, args=(target_ip, q, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    print("=" * 50)
    print(f"Scan selesai. Total open ports: {len(open_ports)}")
    for port, service in sorted(open_ports):
        print(f"  - {port}/{service}")
    print("=" * 50)


if __name__ == "__main__":
    run()
