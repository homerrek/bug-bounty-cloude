#!/usr/bin/env python3
"""
ssl_scanner.py — SSL/TLS configuration scanner.

Tests for weak ciphers, expired certificates, SSL/TLS misconfigurations,
certificate chain issues, and protocol version vulnerabilities.

Usage:
  python3 tools/ssl_scanner.py --host target.com [--port 443]
  python3 tools/ssl_scanner.py --url https://target.com
"""

import argparse
import json
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []

# Weak cipher suites (examples - not exhaustive)
WEAK_CIPHERS = [
    "DES", "3DES", "RC4", "MD5", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "aNULL", "eNULL"
]

# Weak TLS/SSL versions
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def test_certificate(hostname, port):
    """Test SSL certificate validity and properties"""
    print(f"\n{BOLD}[1/5] Testing certificate...{RESET}")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check expiration
                not_after = cert.get("notAfter")
                if not_after:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (expiry_date - datetime.now()).days

                    if days_until_expiry < 0:
                        _add_finding("CRITICAL",
                                   "SSL certificate expired",
                                   f"Certificate expired {abs(days_until_expiry)} days ago",
                                   f"Expired: {not_after}")
                    elif days_until_expiry < 30:
                        _add_finding("HIGH",
                                   "SSL certificate expiring soon",
                                   f"Certificate expires in {days_until_expiry} days",
                                   f"Expires: {not_after}")
                    else:
                        print(f"{GREEN}Certificate valid for {days_until_expiry} days{RESET}")

                # Check subject
                subject = dict(x[0] for x in cert.get("subject", ()))
                cn = subject.get("commonName", "")
                print(f"  Common Name: {cn}")

                # Check for wildcard mismatch
                if cn.startswith("*.") and hostname.count(".") <= 1:
                    _add_finding("MEDIUM",
                               "Wildcard certificate on apex domain",
                               f"Wildcard cert {cn} may not properly cover {hostname}",
                               f"CN: {cn}, Host: {hostname}")

                # Check subject alternative names
                san = cert.get("subjectAltName", ())
                if san:
                    san_names = [name for _, name in san]
                    if hostname not in san_names and f"*.{hostname}" not in san_names:
                        _add_finding("HIGH",
                                   "Hostname not in certificate SAN",
                                   f"Certificate may not be valid for {hostname}",
                                   f"SAN: {san_names}")

    except ssl.SSLError as e:
        _add_finding("HIGH",
                   "SSL handshake failed",
                   f"Could not establish SSL connection: {str(e)}",
                   f"Error: {e}")
    except Exception as e:
        print(f"{YELLOW}[WARNING] Certificate check failed: {e}{RESET}")


def test_protocol_versions(hostname, port):
    """Test for weak SSL/TLS protocol versions"""
    print(f"\n{BOLD}[2/5] Testing protocol versions...{RESET}")

    protocols = [
        ("SSLv2", ssl.PROTOCOL_TLS),  # Will fail if not supported
        ("SSLv3", ssl.PROTOCOL_TLS),
        ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
        ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
        ("TLSv1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
        ("TLSv1.3", ssl.PROTOCOL_TLS),
    ]

    supported = []
    for proto_name, proto_const in protocols:
        if proto_const is None:
            continue

        try:
            context = ssl.SSLContext(proto_const)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Try to set specific protocol version
            if proto_name in ["SSLv2", "SSLv3"]:
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
                continue  # Skip these as they should be disabled

            if proto_name == "TLSv1.0":
                context.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "TLSv1.1":
                context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported.append(proto_name)
                    print(f"  {proto_name}: Supported")

        except Exception:
            pass

    # Check for weak protocols
    for weak_proto in WEAK_PROTOCOLS:
        if weak_proto in supported:
            _add_finding("HIGH",
                       f"Weak protocol {weak_proto} supported",
                       f"{weak_proto} is deprecated and vulnerable to attacks",
                       f"Protocol: {weak_proto}")

    if "TLSv1.2" in supported or "TLSv1.3" in supported:
        print(f"{GREEN}Modern TLS versions supported{RESET}")


def test_cipher_suites(hostname, port):
    """Test for weak cipher suites"""
    print(f"\n{BOLD}[3/5] Testing cipher suites...{RESET}")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, protocol, bits = cipher
                    print(f"  Negotiated cipher: {cipher_name}")
                    print(f"  Protocol: {protocol}")
                    print(f"  Key strength: {bits} bits")

                    # Check for weak ciphers
                    for weak in WEAK_CIPHERS:
                        if weak.upper() in cipher_name.upper():
                            _add_finding("CRITICAL",
                                       f"Weak cipher suite: {cipher_name}",
                                       f"Server accepts weak cipher containing {weak}",
                                       f"Cipher: {cipher_name}")
                            break

                    # Check key strength
                    if bits < 128:
                        _add_finding("HIGH",
                                   f"Weak encryption key: {bits} bits",
                                   "Key strength below 128 bits is considered weak",
                                   f"Bits: {bits}")

    except Exception as e:
        print(f"{YELLOW}[WARNING] Cipher suite check failed: {e}{RESET}")


def test_certificate_chain(hostname, port):
    """Test certificate chain validity"""
    print(f"\n{BOLD}[4/5] Testing certificate chain...{RESET}")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # If we get here, chain is valid
                print(f"{GREEN}Certificate chain is valid{RESET}")

    except ssl.SSLCertVerificationError as e:
        _add_finding("CRITICAL",
                   "Certificate chain verification failed",
                   f"SSL certificate chain is invalid: {str(e)}",
                   f"Error: {e}")
    except Exception as e:
        print(f"{YELLOW}[WARNING] Chain validation check failed: {e}{RESET}")


def test_vulnerabilities(hostname, port):
    """Test for known SSL/TLS vulnerabilities"""
    print(f"\n{BOLD}[5/5] Testing known vulnerabilities...{RESET}")

    # Test for compression (CRIME vulnerability)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if ssock.compression():
                    _add_finding("HIGH",
                               "SSL compression enabled (CRIME vulnerability)",
                               "Server supports SSL compression - vulnerable to CRIME attack",
                               "Compression: Enabled")
                else:
                    print(f"{GREEN}SSL compression disabled{RESET}")
    except Exception as e:
        print(f"  {DIM}Compression check skipped: {e}{RESET}")

    # Note: Full vulnerability testing (BEAST, POODLE, Heartbleed, etc.)
    # requires more complex testing and is better done with tools like testssl.sh
    print(f"  {CYAN}[INFO] Use testssl.sh for comprehensive vulnerability testing{RESET}")


def main():
    parser = argparse.ArgumentParser(description="SSL/TLS configuration scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Target hostname")
    group.add_argument("--url", help="Target URL (https://...)")
    parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.url:
        parsed = urlparse(args.url)
        hostname = parsed.netloc.split(":")[0]
        port = parsed.port or 443
    else:
        hostname = args.host
        port = args.port

    print(f"\n{BOLD}SSL/TLS Scanner{RESET}")
    print(f"Target: {hostname}:{port}\n")

    # Run all tests
    test_certificate(hostname, port)
    test_protocol_versions(hostname, port)
    test_cipher_suites(hostname, port)
    test_certificate_chain(hostname, port)
    test_vulnerabilities(hostname, port)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No SSL/TLS vulnerabilities detected.{RESET}")
        else:
            print(f"{YELLOW}Use 'testssl.sh {hostname}' for comprehensive testing{RESET}")


if __name__ == "__main__":
    main()
