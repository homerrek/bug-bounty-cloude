#!/usr/bin/env python3
"""
cache_deception_scanner — Web Cache Deception vulnerability scanner

Usage:
  python3 tools/cache_deception_scanner.py --url <target> [--cookies <cookie_string>] [--dry-run] [--rate 1.0]
"""

import argparse
import json
import os
import sys
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

CACHE_HEADERS = [
    "Cache-Control", "X-Cache", "Age", "Surrogate-Key",
    "CF-Cache-Status", "X-Drupal-Cache", "Vary", "Pragma",
    "Expires", "CDN-Cache-Control", "X-Cache-Status", "Fastly-Cache-Status",
]

SUFFIXES = [".css", ".js", ".ico", ".png", ".jpg", ".woff", ".gif", ".svg", ".map"]
PARAMS   = ["?v=1", "?cb=1", "?static=true", "?_=1", "?cachebust=1"]


def _sleep():
    time.sleep(REQUEST_INTERVAL)


def _request(url, method="GET", headers=None, body=None, timeout=15):
    """Make HTTP request, return (status_code, headers_dict, body_str)."""
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; BugBountyScanner/1.0)")
    try:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e)


def _add_finding(severity, title, detail, evidence=""):
    f = {"severity": severity, "title": title, "detail": detail, "evidence": evidence}
    FINDINGS.append(f)
    color = RED if severity in ("HIGH", "CRITICAL") else YELLOW if severity == "MEDIUM" else CYAN
    print(f"{color}[{severity}]{RESET} {title}")
    if detail:
        print(f"  {DIM}{detail}{RESET}")
    if evidence:
        print(f"  {BLUE}Evidence: {evidence}{RESET}")


def _is_cached(resp_headers):
    """Return True and reason string if response appears to be cached."""
    reasons = []
    cc = resp_headers.get("Cache-Control", "").lower()
    if "no-store" in cc or "no-cache" in cc or "private" in cc:
        return False, ""
    if resp_headers.get("X-Cache", "").lower() in ("hit", "hit from cloudfront"):
        reasons.append("X-Cache: HIT")
    if resp_headers.get("CF-Cache-Status", "").upper() == "HIT":
        reasons.append("CF-Cache-Status: HIT")
    if resp_headers.get("X-Cache-Status", "").upper() == "HIT":
        reasons.append("X-Cache-Status: HIT")
    age = resp_headers.get("Age", "")
    if age and age.strip() != "0":
        reasons.append(f"Age: {age}")
    if resp_headers.get("Surrogate-Key"):
        reasons.append(f"Surrogate-Key present")
    if "public" in cc and ("max-age" in cc or "s-maxage" in cc):
        reasons.append(f"Cache-Control: {cc}")
    return bool(reasons), ", ".join(reasons)


def _contains_auth_data(body, cookies):
    """Heuristic: response body contains account-specific data."""
    if not cookies:
        return False
    keywords = [
        "email", "username", "account", "profile", "user_id", "userid",
        "name", "phone", "address", "token", "csrf", "session",
    ]
    body_lower = body.lower()
    return any(kw in body_lower for kw in keywords)


def _cache_header_summary(resp_headers):
    summary = {}
    for h in CACHE_HEADERS:
        val = resp_headers.get(h)
        if val:
            summary[h] = val
    return summary


def test_suffix_confusion(base_url, cookies, dry_run):
    print(f"\n{BOLD}[*] Testing path suffix confusion...{RESET}")
    req_headers = {}
    if cookies:
        req_headers["Cookie"] = cookies

    # Variants for each suffix
    for suffix in SUFFIXES:
        variants = [
            base_url + suffix,
            base_url.rstrip("/") + "/fake" + suffix,
            base_url + ";" + suffix,
        ]
        for url in variants:
            if dry_run:
                print(f"  {DIM}[dry-run] GET {url}{RESET}")
                continue
            print(f"  {DIM}Testing: {url}{RESET}")
            status, headers, body = _request(url, headers=dict(req_headers))
            _sleep()
            cached, reason = _is_cached(headers)
            has_auth = _contains_auth_data(body, cookies)
            header_summary = _cache_header_summary(headers)
            if cached and has_auth:
                _add_finding(
                    "HIGH",
                    f"Web Cache Deception — authenticated response cached for {suffix}",
                    f"URL: {url} | Status: {status} | Cache indicators: {reason}",
                    json.dumps(header_summary),
                )
            elif cached:
                _add_finding(
                    "MEDIUM",
                    f"Cache Deception — response cached for path with {suffix}",
                    f"URL: {url} | Status: {status} | {reason}",
                    json.dumps(header_summary),
                )
            elif header_summary:
                print(f"  {GREEN}[INFO]{RESET} Cache headers present but not cached: {header_summary}")


def test_param_deception(base_url, cookies, dry_run):
    print(f"\n{BOLD}[*] Testing parameter-based cache deception...{RESET}")
    req_headers = {}
    if cookies:
        req_headers["Cookie"] = cookies

    for param in PARAMS:
        url = base_url + param
        if dry_run:
            print(f"  {DIM}[dry-run] GET {url}{RESET}")
            continue
        print(f"  {DIM}Testing: {url}{RESET}")
        status, headers, body = _request(url, headers=dict(req_headers))
        _sleep()
        cached, reason = _is_cached(headers)
        has_auth = _contains_auth_data(body, cookies)
        header_summary = _cache_header_summary(headers)
        if cached and has_auth:
            _add_finding(
                "MEDIUM",
                f"Cache Deception via query param — authenticated response cached ({param})",
                f"URL: {url} | Status: {status} | {reason}",
                json.dumps(header_summary),
            )
        elif cached:
            print(f"  {CYAN}[INFO]{RESET} Response cached for {url}: {reason}")


def main():
    parser = argparse.ArgumentParser(description="Web Cache Deception vulnerability scanner")
    parser.add_argument("--url", required=True, help="Target authenticated URL")
    parser.add_argument("--cookies", default="", help="Cookie header value for authenticated requests")
    parser.add_argument("--dry-run", action="store_true", help="Show payloads without sending")
    parser.add_argument("--rate", type=float, default=1.0, help="Requests per second (default: 1.0)")
    parser.add_argument("--json", dest="json_out", action="store_true", help="Output JSON")
    args = parser.parse_args()

    global REQUEST_INTERVAL
    REQUEST_INTERVAL = 1.0 / args.rate if args.rate > 0 else 1.0

    print(f"{BOLD}{CYAN}=== Web Cache Deception Scanner ==={RESET}")
    print(f"Target: {args.url}")
    if args.cookies:
        print(f"Cookies: {args.cookies[:40]}{'...' if len(args.cookies) > 40 else ''}")

    test_suffix_confusion(args.url, args.cookies, args.dry_run)
    test_param_deception(args.url, args.cookies, args.dry_run)

    if args.json_out:
        print(json.dumps({"findings": FINDINGS}, indent=2))
    else:
        print(f"\n{BOLD}Summary: {len(FINDINGS)} finding(s){RESET}")
        if not FINDINGS:
            print(f"{GREEN}No cache deception issues found.{RESET}")


if __name__ == "__main__":
    main()
