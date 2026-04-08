#!/usr/bin/env python3
"""
cors_scanner.py — CORS misconfiguration scanner.

Tests for origin reflection, null-origin acceptance, subdomain wildcards,
pre-flight weakness, credential exposure, and internal-network CORS leaks.

Usage:
  python3 tools/cors_scanner.py --target https://app.example.com/api/data
  python3 tools/cors_scanner.py --target https://app.example.com/ --dry-run
  python3 tools/cors_scanner.py --target https://app.example.com/ --rate 0.5 --json
  python3 tools/cors_scanner.py --url https://app.example.com/ --rate 2.0
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

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

# ─── Probe origins ────────────────────────────────────────────────────────────

# Injected evil domain to detect reflection
EVIL_ORIGIN = "https://evil-cors-test.com"

# Internal IP ranges for internal-network probe
INTERNAL_ORIGINS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
]


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


def _acao(headers: dict) -> str:
    """Return Access-Control-Allow-Origin value or empty string."""
    return headers.get("access-control-allow-origin", "")


def _acac(headers: dict) -> str:
    """Return Access-Control-Allow-Credentials value or empty string."""
    return headers.get("access-control-allow-credentials", "")


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_origin_reflection(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] Origin Reflection{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send Origin: {EVIL_ORIGIN} → check ACAO reflection")
        return
    time.sleep(1.0 / rate)
    status, headers, body = http_get(url, {"Origin": EVIL_ORIGIN})
    acao = _acao(headers)
    acac = _acac(headers)
    if acao == EVIL_ORIGIN:
        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
        detail = f"ACAO: {acao}, ACAC: {acac or 'not set'}"
        record("origin-reflection", "VULNERABLE", detail, severity)
    elif acao == "*":
        record("origin-wildcard", "INTERESTING",
               "Wildcard ACAO — dangerous if ACAC ever enabled", "LOW")
    else:
        record("origin-reflection", "SAFE", f"ACAO: {acao or 'not set'}")


def test_null_origin(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] Null Origin (Sandboxed Iframe Bypass){RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send Origin: null → check ACAO == 'null'")
        return
    time.sleep(1.0 / rate)
    status, headers, body = http_get(url, {"Origin": "null"})
    acao = _acao(headers)
    acac = _acac(headers)
    if acao == "null":
        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
        record("null-origin", "VULNERABLE",
               f"ACAO: null accepted — sandboxed iframe bypass. ACAC: {acac or 'not set'}",
               severity)
    else:
        record("null-origin", "SAFE", f"ACAO: {acao or 'not set'}")


def test_subdomain_wildcard(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] Subdomain Wildcard{RESET}")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    # Strip leading 'www.' for a cleaner base domain
    base = re.sub(r"^www\.", "", host)
    evil_sub = f"https://evil.{base}"
    extra_sub = f"https://notreally{base}"

    for probe_origin, label in [(evil_sub, "evil subdomain"), (extra_sub, "domain suffix match")]:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would send Origin: {probe_origin}")
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(url, {"Origin": probe_origin})
        acao = _acao(headers)
        acac = _acac(headers)
        if acao == probe_origin:
            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            record(f"subdomain-wildcard-{label.replace(' ', '-')}", "VULNERABLE",
                   f"Reflected arbitrary subdomain. ACAO: {acao}, ACAC: {acac or 'not set'}",
                   severity)
        else:
            record(f"subdomain-wildcard-{label.replace(' ', '-')}", "SAFE",
                   f"ACAO: {acao or 'not set'}")


def test_preflight_bypass(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] Pre-flight Bypass (OPTIONS){RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send OPTIONS with dangerous headers/methods")
        return

    # Build an OPTIONS request manually
    req_headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
        "Origin": EVIL_ORIGIN,
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
    }
    time.sleep(1.0 / rate)
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    req = urllib.request.Request(url, headers=req_headers, method="OPTIONS")
    try:
        with opener.open(req, timeout=10) as r:
            resp_headers = {}
            for k in r.headers:
                resp_headers[k.lower()] = r.headers[k]
    except urllib.error.HTTPError as e:
        resp_headers = {}
        for k in e.headers:
            resp_headers[k.lower()] = e.headers[k]
    except Exception as e:
        record("preflight-options", "ERROR", str(e))
        return

    acam = resp_headers.get("access-control-allow-methods", "")
    acah = resp_headers.get("access-control-allow-headers", "")
    acao = _acao(resp_headers)

    issues = []
    if "*" in acam:
        issues.append(f"ACAM=* (all methods allowed)")
    if "*" in acah:
        issues.append(f"ACAH=* (all headers allowed)")
    if acao == EVIL_ORIGIN:
        issues.append(f"ACAO reflects evil origin in preflight")

    if issues:
        record("preflight-bypass", "VULNERABLE", "; ".join(issues), "MEDIUM")
    elif acam or acah:
        record("preflight-bypass", "INTERESTING",
               f"Preflight responded — ACAM: {acam or '-'}, ACAH: {acah or '-'}", "LOW")
    else:
        record("preflight-bypass", "SAFE", "No permissive preflight response")


def test_credential_exposure(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[5] Credential Exposure (ACAC: true + reflected origin){RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send Origin: {EVIL_ORIGIN} + Cookie → check ACAO+ACAC combo")
        return
    time.sleep(1.0 / rate)
    status, headers, body = http_get(url, {
        "Origin": EVIL_ORIGIN,
        "Cookie": "session=test-credential-probe",
    })
    acao = _acao(headers)
    acac = _acac(headers)
    if acao == EVIL_ORIGIN and acac.lower() == "true":
        record("credential-exposure", "VULNERABLE",
               "ACAO reflects attacker origin AND ACAC=true — credentials exposed cross-origin",
               "CRITICAL")
    elif acao == "*" and acac.lower() == "true":
        # The CORS spec prohibits ACAO=* alongside ACAC=true; all compliant
        # browsers will reject this combination and block the response.
        # Flag as INTERESTING because the server is misconfigured — a future
        # spec change or non-browser client could exploit it.
        record("credential-exposure", "INTERESTING",
               "ACAO=* with ACAC=true — violates CORS spec, browsers reject this "
               "combination, but server is misconfigured", "LOW")
    else:
        record("credential-exposure", "SAFE",
               f"ACAO: {acao or 'not set'}, ACAC: {acac or 'not set'}")


def test_internal_network_cors(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[6] Internal Network Origin Acceptance{RESET}")
    for origin in INTERNAL_ORIGINS:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would send Origin: {origin}")
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(url, {"Origin": origin})
        acao = _acao(headers)
        if acao == origin:
            record(f"internal-cors-{origin}", "VULNERABLE",
                   f"Internal origin accepted: {origin} → ACAO: {acao}", "HIGH")
        else:
            record(f"internal-cors-{origin}", "SAFE",
                   f"Origin {origin} → ACAO: {acao or 'not set'}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CORS misconfiguration scanner")
    # --target is primary; --url is accepted as an alias for backward compatibility
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", metavar="URL", help="Target URL to test")
    target_group.add_argument("--url",    metavar="URL", help="Alias for --target")
    parser.add_argument("--url-list", metavar="FILE",
                        help="File of URLs to test (one per line)")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show probes without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    target = args.target or args.url

    # Build list of targets
    targets = [target]
    if args.url_list:
        try:
            with open(args.url_list) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as e:
            print(f"{RED}[ERROR]{RESET} Cannot read --url-list: {e}", file=sys.stderr)
            sys.exit(1)

    for url in targets:
        print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
        print(f"║   CORS Misconfiguration Scanner      ║")
        print(f"╚══════════════════════════════════════╝{RESET}")
        print(f"  Target : {CYAN}{url}{RESET}")
        print(f"  Rate   : {args.rate} req/sec")
        if args.dry_run:
            print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

        test_origin_reflection(url, args.rate, args.dry_run)
        test_null_origin(url, args.rate, args.dry_run)
        test_subdomain_wildcard(url, args.rate, args.dry_run)
        test_preflight_bypass(url, args.rate, args.dry_run)
        test_credential_exposure(url, args.rate, args.dry_run)
        test_internal_network_cors(url, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] == "VULNERABLE"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run  : {len(FINDINGS)}")
    if vulns:
        print(f"  {RED}Vulnerable : {len(vulns)}{RESET}")
        for f in vulns:
            sev = f.get("severity", "")
            print(f"    {RED}→{RESET} [{sev}] {f['test']}: {f['detail']}")
    else:
        print(f"  {GREEN}Vulnerable : 0{RESET}")

    if args.json_output:
        print(json.dumps({"targets": targets, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
