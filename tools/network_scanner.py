#!/usr/bin/env python3
"""
network_scanner.py — Network service scanner and port analyzer.

Performs port scanning, service detection, banner grabbing, and
identifies common misconfigurations on discovered services.

Usage:
  python3 tools/network_scanner.py --host target.com [--ports 80,443,8080]
  python3 tools/network_scanner.py --host target.com --fast
  python3 tools/network_scanner.py --host target.com --full
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []
OPEN_PORTS = []

# Common ports and their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 3000: "Node.js"
}

# Dangerous/insecure services
DANGEROUS_SERVICES = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    445: "SMB (ransomware vector)",
    3389: "RDP (brute force target)",
    5900: "VNC (weak auth)",
    6379: "Redis (often unauth)",
    9200: "Elasticsearch (data exposure)",
    27017: "MongoDB (unauth access)"
}


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def scan_port(host, port, timeout=2):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host, port, timeout=3):
    """Attempt to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Try to receive banner
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        # For HTTP services, try sending a request
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            if "HTTP" in banner or "Server:" in banner:
                # Extract Server header
                for line in banner.split("\n"):
                    if line.startswith("Server:"):
                        return line.strip()
            return banner[:100] if banner else None
        except Exception:
            return None


def check_redis_unauth(host, port):
    """Check if Redis allows unauthenticated access"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b"INFO\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()

        if "redis_version" in response.lower():
            return True
    except Exception:
        pass
    return False


def check_mongodb_unauth(host, port):
    """Check if MongoDB allows unauthenticated access"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        # MongoDB wire protocol handshake attempt
        sock.close()
        return True  # If connection succeeds, further testing needed
    except Exception:
        return False


def analyze_service(host, port, banner):
    """Analyze service for vulnerabilities"""
    service = COMMON_PORTS.get(port, "Unknown")

    # Check if it's a dangerous service
    if port in DANGEROUS_SERVICES:
        _add_finding("HIGH",
                   f"Dangerous service exposed: {DANGEROUS_SERVICES[port]}",
                   f"Port {port} ({service}) is publicly accessible",
                   f"Port: {port}, Service: {service}")

    # Banner analysis
    if banner:
        print(f"    Banner: {banner[:100]}")

        # Check for version disclosure
        if any(ver in banner.lower() for ver in ["apache", "nginx", "iis", "version", "v"]):
            _add_finding("MEDIUM",
                       f"Version disclosure on port {port}",
                       "Service banner reveals version information",
                       f"Banner: {banner[:100]}")

    # Service-specific checks
    if port == 6379:  # Redis
        if check_redis_unauth(host, port):
            _add_finding("CRITICAL",
                       "Redis allows unauthenticated access",
                       "Redis is accessible without authentication - full data access!",
                       f"Host: {host}:{port}")

    if port == 27017:  # MongoDB
        if check_mongodb_unauth(host, port):
            _add_finding("HIGH",
                       "MongoDB port accessible",
                       "MongoDB may allow unauthenticated access - manual verification needed",
                       f"Host: {host}:{port}")

    if port == 9200:  # Elasticsearch
        _add_finding("HIGH",
                   "Elasticsearch exposed",
                   "Elasticsearch is publicly accessible - check for unauth access",
                   f"Host: {host}:{port}")

    if port in [21, 23]:  # FTP, Telnet
        _add_finding("HIGH",
                   f"Unencrypted protocol: {service}",
                   f"{service} transmits credentials in cleartext",
                   f"Port: {port}")


def scan_host(host, ports, threads=10):
    """Scan multiple ports on a host"""
    print(f"\n{BOLD}Scanning {host}...{RESET}\n")

    open_count = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}

        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_count += 1
                    service = COMMON_PORTS.get(port, "Unknown")
                    print(f"{GREEN}[OPEN]{RESET} Port {port} ({service})")

                    OPEN_PORTS.append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })

                    # Grab banner
                    print(f"  {DIM}Grabbing banner...{RESET}")
                    banner = grab_banner(host, port)

                    # Analyze service
                    analyze_service(host, port, banner)

            except Exception as e:
                print(f"{YELLOW}[ERROR] Port {port}: {e}{RESET}")

    print(f"\n{BOLD}Total open ports: {open_count}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Network service scanner")
    parser.add_argument("--host", required=True, help="Target hostname or IP")
    parser.add_argument("--ports", help="Comma-separated ports (e.g., 80,443,8080)")
    parser.add_argument("--fast", action="store_true", help="Scan only top 20 ports")
    parser.add_argument("--full", action="store_true", help="Scan top 1000 ports")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    print(f"\n{BOLD}Network Service Scanner{RESET}")
    print(f"Target: {args.host}\n")

    # Determine port list
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    elif args.fast:
        # Top 20 ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 3000]
    elif args.full:
        # Top 1000 ports (simplified - just common ones for demo)
        ports = list(COMMON_PORTS.keys()) + list(range(8000, 8100)) + list(range(9000, 9100))
    else:
        # Default: common web + database ports
        ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]

    print(f"Scanning {len(ports)} ports with {args.threads} threads\n")

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(args.host)
        print(f"Resolved {args.host} -> {ip}\n")
    except socket.gaierror:
        print(f"{RED}[ERROR] Could not resolve hostname: {args.host}{RESET}")
        sys.exit(1)

    # Scan
    scan_host(ip, ports, args.threads)

    if args.json_out:
        output = {
            "findings": FINDINGS,
            "open_ports": OPEN_PORTS
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No critical network issues detected.{RESET}")
        else:
            print(f"{YELLOW}Recommendation: Use nmap for comprehensive scanning{RESET}")


if __name__ == "__main__":
    main()
