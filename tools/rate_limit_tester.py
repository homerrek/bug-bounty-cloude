#!/usr/bin/env python3
"""
rate_limit_tester.py — Rate limit bypass scanner.

Tests IP rotation headers, endpoint case variation, parameter padding,
HTTP method swap, null byte bypass, and Unicode padding to find rate limit gaps.

Usage:
  python3 tools/rate_limit_tester.py --url https://api.example.com/login --method POST
  python3 tools/rate_limit_tester.py --url https://api.example.com/login --method POST --param email --requests 30
  python3 tools/rate_limit_tester.py --url https://api.example.com/login --dry-run
  python3 tools/rate_limit_tester.py --url https://api.example.com/login --rate 2.0 --json
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import random
import string

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

# ─── Bypass technique definitions ─────────────────────────────────────────────

IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
    "Forwarded",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Host",
    "X-ProxyUser-Ip",
]


def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_string(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_request(url: str, method: str, body: dict | None = None,
                  extra_headers: dict | None = None,
                  timeout: int = 10) -> tuple[int, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def record(test: str, result: str, detail: str, severity: str = "MEDIUM"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "BYPASS" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


def send_n_requests(url: str, method: str, body: dict | None,
                     extra_headers: dict | None, n: int,
                     rate: float, label: str) -> list[int]:
    """Send N requests and return list of status codes."""
    statuses = []
    for i in range(n):
        time.sleep(1.0 / rate)
        # Rotate IP if IP header is present
        if extra_headers:
            for h in IP_HEADERS:
                if h in extra_headers:
                    extra_headers[h] = random_ip()
        status, _ = http_request(url, method, body, extra_headers)
        statuses.append(status)
        print(f"    {DIM}[{i+1:02d}/{n}] HTTP {status}{RESET}", end="\r")
    print()
    return statuses


def analyze_statuses(statuses: list[int], baseline: list[int], test_name: str):
    """Compare test statuses to baseline — flag if bypass signal seen."""
    baseline_429 = sum(1 for s in baseline if s == 429)
    test_429     = sum(1 for s in statuses if s == 429)
    test_200     = sum(1 for s in statuses if s == 200)
    test_2xx     = sum(1 for s in statuses if 200 <= s < 300)

    if baseline_429 > 0 and test_429 == 0 and test_2xx > 0:
        record(test_name, "BYPASS",
               f"Baseline got {baseline_429}× 429 — test got 0× 429, {test_2xx}× 2xx")
    elif test_429 < baseline_429 and test_2xx > 0:
        record(test_name, "INTERESTING",
               f"Fewer 429s: baseline={baseline_429} → test={test_429}")
    else:
        record(test_name, "BLOCKED",
               f"429s: baseline={baseline_429}, test={test_429}")


# ─── Bypass Tests ─────────────────────────────────────────────────────────────

def test_baseline(url: str, method: str, body: dict | None,
                   n: int, rate: float, dry_run: bool) -> list[int]:
    print(f"\n{BOLD}[0] Baseline — {n} requests, no bypass{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send {n} {method} to {url}")
        return [200] * n
    statuses = send_n_requests(url, method, body, None, n, rate, "baseline")
    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    print(f"  {DIM}Status distribution: {counts}{RESET}")
    return statuses


def test_ip_rotation_headers(url: str, method: str, body: dict | None,
                               n: int, rate: float, dry_run: bool,
                               baseline: list[int]):
    print(f"\n{BOLD}[1] IP Rotation Headers{RESET}")
    for header in IP_HEADERS:
        extra = {header: random_ip()}
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} {header}: {random_ip()}")
            continue
        statuses = send_n_requests(url, method, body, extra, n, rate, header)
        analyze_statuses(statuses, baseline, f"ip-header:{header}")


def test_case_variation(url: str, method: str, body: dict | None,
                         n: int, rate: float, dry_run: bool,
                         baseline: list[int]):
    print(f"\n{BOLD}[2] Endpoint Case Variation{RESET}")
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path

    variations = []
    if path:
        variations += [
            ("upper",      url.replace(path, path.upper())),
            ("mixed",      url.replace(path, "".join(
                c.upper() if i % 2 == 0 else c for i, c in enumerate(path)))),
        ]
    # Add trailing slash / double slash
    variations += [
        ("trailing-slash",   url.rstrip("/") + "/"),
        ("double-slash",     urllib.parse.urlunparse(parsed._replace(path="/" + parsed.path.lstrip("/")))),
    ]

    for name, var_url in variations:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} {name}: {var_url}")
            continue
        statuses = send_n_requests(var_url, method, body, None, n, rate, name)
        analyze_statuses(statuses, baseline, f"case-var:{name}")


def test_param_padding(url: str, method: str, body: dict | None,
                        param: str, n: int, rate: float,
                        dry_run: bool, baseline: list[int]):
    print(f"\n{BOLD}[3] Parameter Padding{RESET}")
    if not param or not body:
        print(f"  {DIM}Skipped — use --param <name> with a JSON body{RESET}")
        return

    techniques = [
        ("extra-whitespace",  {**body, param: body.get(param, "") + "  "}),
        ("null-byte",         {**body, param: body.get(param, "") + "\x00"}),
        ("unicode-padding",   {**body, param: body.get(param, "") + "\u0000"}),
        ("extra-param",       {**body, f"_pad_{random_string()}": 1}),
        ("array-wrap",        {**body, param: [body.get(param, "")]}),
        ("case-param",        {param.upper(): body.get(param, ""), **{k: v for k, v in body.items() if k != param}}),
    ]
    for name, padded_body in techniques:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} {name}: {json.dumps(padded_body)[:80]}")
            continue
        statuses = send_n_requests(url, method, padded_body, None, n, rate, name)
        analyze_statuses(statuses, baseline, f"param-pad:{name}")


def test_method_swap(url: str, method: str, body: dict | None,
                      n: int, rate: float, dry_run: bool,
                      baseline: list[int]):
    print(f"\n{BOLD}[4] HTTP Method Swap{RESET}")
    alt_methods = [m for m in ("GET", "POST", "PUT", "PATCH", "OPTIONS") if m != method]
    for alt in alt_methods:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would try {alt} {url}")
            continue
        statuses = send_n_requests(url, alt, body, None, n, rate, alt)
        analyze_statuses(statuses, baseline, f"method-swap:{alt}")


def test_header_bypass(url: str, method: str, body: dict | None,
                        n: int, rate: float, dry_run: bool,
                        baseline: list[int]):
    print(f"\n{BOLD}[5] Header-Based Bypass Techniques{RESET}")
    bypass_headers = [
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Forwarded-Host",          "localhost"),
        ("Content-Type",              "application/x-www-form-urlencoded"),
        ("X-HTTP-Method-Override",    "GET"),
        ("X-Method-Override",         "GET"),
    ]
    for hname, hval in bypass_headers:
        extra = {hname: hval}
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} {hname}: {hval}")
            continue
        statuses = send_n_requests(url, method, body, extra, n, rate, hname)
        analyze_statuses(statuses, baseline, f"header-bypass:{hname}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Rate limit bypass tester")
    parser.add_argument("--url",      required=True, help="Target endpoint URL")
    parser.add_argument("--method",   default="POST",
                        choices=["GET", "POST", "PUT", "PATCH", "DELETE"],
                        help="HTTP method (default: POST)")
    parser.add_argument("--param",    default="",
                        help="Body parameter to apply padding techniques to")
    parser.add_argument("--body",     default="{}",
                        help='JSON body to send (default: {})')
    parser.add_argument("--requests", type=int, default=20, dest="n",
                        metavar="N", help="Requests per bypass technique (default: 20)")
    parser.add_argument("--rate",     type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Show what would be tested without sending requests")
    parser.add_argument("--json",     action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    try:
        body = json.loads(args.body) if args.body != "{}" else None
    except json.JSONDecodeError:
        print(f"{RED}[ERROR]{RESET} Invalid JSON in --body")
        sys.exit(1)

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   Rate Limit Bypass Tester           ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target   : {CYAN}{args.url}{RESET}")
    print(f"  Method   : {args.method}")
    print(f"  Requests : {args.n} per technique")
    print(f"  Rate     : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode     : {YELLOW}DRY-RUN (no requests sent){RESET}")

    baseline = test_baseline(args.url, args.method, body, args.n, args.rate, args.dry_run)
    test_ip_rotation_headers(args.url, args.method, body, args.n, args.rate, args.dry_run, baseline)
    test_case_variation(args.url, args.method, body, args.n, args.rate, args.dry_run, baseline)
    test_param_padding(args.url, args.method, body, args.param, args.n, args.rate, args.dry_run, baseline)
    test_method_swap(args.url, args.method, body, args.n, args.rate, args.dry_run, baseline)
    test_header_bypass(args.url, args.method, body, args.n, args.rate, args.dry_run, baseline)

    bypasses = [f for f in FINDINGS if f["result"] == "BYPASS"]
    interesting = [f for f in FINDINGS if f["result"] == "INTERESTING"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run   : {len(FINDINGS)}")
    if bypasses:
        print(f"  {RED}Bypasses    : {len(bypasses)}{RESET}")
        for f in bypasses:
            print(f"    {RED}→{RESET} {f['test']}: {f['detail']}")
    else:
        print(f"  {GREEN}Bypasses    : 0{RESET}")
    if interesting:
        print(f"  {YELLOW}Interesting : {len(interesting)}{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
