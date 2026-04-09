#!/usr/bin/env python3
"""
host_header_scanner.py — Host header injection scanner.

Tests for Host header poisoning: password reset link poisoning,
web cache poisoning via Host, routing-based SSRF.

Usage:
  python3 tools/host_header_scanner.py --url https://target.com [--callback evil.com]
  python3 tools/host_header_scanner.py --url https://target.com --dry-run
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []
REQUEST_INTERVAL = 1.0


def _sleep():
    time.sleep(REQUEST_INTERVAL)


def _request(url, method="GET", headers=None, timeout=15):
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; BugBountyScanner/1.0)")
    try:
        req = urllib.request.Request(url, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def _get_host(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.split(":")[0]


def scan(target_url, callback, dry_run):
    original_host = _get_host(target_url)
    attacker_host = callback if callback else "evil.attacker.com"

    variants = [
        ("Host", attacker_host),
        ("X-Forwarded-Host", attacker_host),
        ("X-Host", attacker_host),
        ("X-Forwarded-Server", attacker_host),
        ("X-HTTP-Host-Override", attacker_host),
        ("Forwarded", f"host={attacker_host}"),
    ]

    # Also test password reset specific paths
    parsed = urllib.parse.urlparse(target_url)
    reset_paths = ["/password-reset", "/forgot-password", "/reset", "/account/password",
                   "/auth/forgot", "/users/password/new"]

    print(f"\n{BOLD}Host Header Injection Scanner{RESET}")
    print(f"Target: {target_url}")
    print(f"Original Host: {original_host}")
    print(f"Attacker Host: {attacker_host}")
    print(f"Mode: {'DRY RUN' if dry_run else 'ACTIVE'}\n")

    if dry_run:
        print(f"{CYAN}[DRY-RUN] Would test these Host variants:{RESET}")
        for hdr, val in variants:
            print(f"  {hdr}: {val}")
        print(f"\n{CYAN}[DRY-RUN] Would test password reset paths:{RESET}")
        for p in reset_paths:
            print(f"  {parsed.scheme}://{original_host}{p}")
        return

    # Baseline
    status0, hdrs0, body0 = _request(target_url)

    for hdr_name, hdr_val in variants:
        _sleep()
        hdrs = {hdr_name: hdr_val}
        status, resp_hdrs, body = _request(target_url, headers=hdrs)

        reflected = hdr_val in body
        loc = resp_hdrs.get("Location", "")
        reflected_in_loc = hdr_val in loc

        if reflected or reflected_in_loc:
            where = "Location header" if reflected_in_loc else "response body"
            _add_finding("HIGH",
                         f"Host header reflected via {hdr_name}",
                         f"Value '{hdr_val}' appeared in {where}",
                         f"{hdr_name}: {hdr_val}")

    # Test reset paths
    print(f"\n{BOLD}Testing password reset paths...{RESET}")
    for path in reset_paths:
        url = f"{parsed.scheme}://{original_host}{path}"
        _sleep()
        status, resp_hdrs, body = _request(url, headers={"Host": attacker_host})
        if status not in (404, 0) and attacker_host in body:
            _add_finding("HIGH",
                         f"Password reset link poisoning at {path}",
                         f"Attacker host reflected in reset endpoint response",
                         f"Host: {attacker_host} → {status}")
        elif status not in (404, 0):
            print(f"  {YELLOW}[CHECK] {path} → {status} (manual verification needed){RESET}")


def main():
    parser = argparse.ArgumentParser(description="Host header injection scanner")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--callback", help="Attacker-controlled domain for OOB testing")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be tested")
    parser.add_argument("--rate", type=float, default=1.0, help="Requests per second")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    global REQUEST_INTERVAL
    REQUEST_INTERVAL = 1.0 / args.rate if args.rate > 0 else 1.0

    scan(args.url, args.callback, args.dry_run)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No Host header injection detected.{RESET}")


if __name__ == "__main__":
    main()
