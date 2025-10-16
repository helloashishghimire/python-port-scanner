#!/usr/bin/env python3
"""
simple_port_scanner.py

A compact, well-commented port scanner for learning and authorized testing.

Features:
- Hostname or IP (single) or CIDR range (e.g., 192.168.1.0/28)
- Threaded scanning using concurrent.futures
- Optional banner grabbing
- Timeout and graceful error handling
- Easy to read output

Usage examples:
  python simple_port_scanner.py --host example.com --ports 1-1024 --banner
  python simple_port_scanner.py --host 192.168.1.10 --ports 22,80,443
  python simple_port_scanner.py --cidr 192.168.1.0/28 --ports 22,80 --workers 50
"""

import socket
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional

# Default timeout for socket operations (seconds)
SOCKET_TIMEOUT = 1.0

def parse_ports(port_str: str) -> List[int]:
    """
    Parse a port specification string into a list of ports.
    Accepts:
      - "22,80,443"
      - "1-1024"
      - "22,80-90,443"
    """
    ports = set()
    pieces = port_str.split(',')
    for p in pieces:
        p = p.strip()
        if '-' in p:
            start, end = p.split('-', 1)
            start = int(start)
            end = int(end)
            ports.update(range(start, end + 1))
        else:
            ports.add(int(p))
    # Ensure ports are valid and return sorted list
    return sorted([port for port in ports if 1 <= port <= 65535])

def banner_grab(ip: str, port: int, timeout: float = SOCKET_TIMEOUT) -> Optional[str]:
    """
    Try to read a short banner from an open TCP port.
    Returns a decoded banner (trimmed) or None on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # try to receive a little data (may block if service doesn't send a banner)
            try:
                data = sock.recv(1024)
                if data:
                    # return a safe, trimmed string
                    return data.decode(errors='replace').strip()
            except socket.timeout:
                return None
    except Exception:
        return None
    return None

def scan_port(ip: str, port: int, do_banner: bool = False, timeout: float = SOCKET_TIMEOUT) -> Tuple[int, bool, Optional[str]]:
    """
    Attempt to connect to a single TCP port.
    Returns a tuple: (port, is_open, banner_or_None)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = None
                if do_banner:
                    # Attempt to grab banner but do it non-blocking via a separate call
                    banner = banner_grab(ip, port, timeout=timeout)
                return port, True, banner
            else:
                return port, False, None
    except Exception:
        return port, False, None

def scan_host(ip: str, ports: List[int], workers: int = 100, do_banner: bool = False, timeout: float = SOCKET_TIMEOUT):
    """
    Scan the provided ports on a single host using a ThreadPoolExecutor.
    Yields results as (port, is_open, banner)
    """
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, do_banner, timeout): port for port in ports
        }
        for future in as_completed(future_to_port):
            port, is_open, banner = future.result()
            results.append((port, is_open, banner))
    # sort results by port number
    for port, is_open, banner in sorted(results, key=lambda x: x[0]):
        yield port, is_open, banner

def expand_targets(host: Optional[str], cidr: Optional[str]) -> List[str]:
    """
    Return a list of target IP strings from either a single host or a CIDR range.
    """
    targets = []
    if host:
        # resolve hostname to IP (IPv4 only here)
        try:
            ip = socket.gethostbyname(host)
            targets.append(ip)
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve host '{host}': {e}")
    if cidr:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            for ip in network.hosts():  # skip network and broadcast addresses for IPv4
                targets.append(str(ip))
        except ValueError as e:
            raise ValueError(f"Invalid CIDR '{cidr}': {e}")
    return targets

def pretty_print_results(ip: str, results: List[Tuple[int, bool, Optional[str]]]):
    """
    Nicely print scan results for a single IP.
    """
    open_ports = [r for r in results if r[1]]
    print("=" * 60)
    print(f"Scan results for {ip} — {len(open_ports)} open port(s)")
    print("-" * 60)
    if open_ports:
        for port, is_open, banner in sorted(open_ports, key=lambda x: x[0]):
            line = f"Port {port}/tcp — OPEN"
            if banner:
                # trim long banners for readability
                b = banner.replace('\n', ' ').strip()
                if len(b) > 200:
                    b = b[:197] + "..."
                line += f" — Banner: {b}"
            print(line)
    else:
        print("No open ports found in the scanned range.")
    print()

def main():
    parser = argparse.ArgumentParser(description="Simple threaded Python port scanner (for authorized testing)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", "-H", help="Hostname or IPv4 address to scan (e.g., example.com or 192.168.1.10)")
    group.add_argument("--cidr", "-C", help="CIDR range to scan (e.g., 192.168.1.0/28)")
    parser.add_argument("--ports", "-p", required=True, help="Ports to scan. Examples: 22,80,443 or 1-1024 or combo: 1-1024,8080")
    parser.add_argument("--workers", "-w", type=int, default=100, help="Number of concurrent workers (default: 100)")
    parser.add_argument("--banner", action="store_true", help="Attempt simple banner grabbing on open ports")
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT, help=f"Socket timeout in seconds (default: {SOCKET_TIMEOUT})")

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print(f"[!] Invalid ports specification: {e}")
        return

    try:
        targets = expand_targets(args.host, args.cidr)
    except ValueError as e:
        print(f"[!] {e}")
        return

    if not targets:
        print("[!] No targets resolved. Exiting.")
        return

    # Scan each target sequentially (parallelizing across ports per host)
    for ip in targets:
        results = list(scan_host(ip, ports, workers=args.workers, do_banner=args.banner, timeout=args.timeout))
        pretty_print_results(ip, results)

if __name__ == "__main__":
    main()

