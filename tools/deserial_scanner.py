#!/usr/bin/env python3
"""
deserial_scanner.py — Insecure deserialization detector.

Scans HTTP responses for serialized object signatures in cookies, headers,
and response bodies. Identifies Java, PHP, Python pickle, and .NET ViewState
deserialization candidates.

Usage:
  python3 tools/deserial_scanner.py --url https://app.example.com/
  python3 tools/deserial_scanner.py --url https://app.example.com/ --dry-run
  python3 tools/deserial_scanner.py --url https://app.example.com/ --rate 0.5 --json
  python3 tools/deserial_scanner.py --url https://app.example.com/ --cookie "JSESSIONID=..."
"""

import argparse
import base64
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import re

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

# ─── Serialization signatures ─────────────────────────────────────────────────

# Java serialized object: starts with 0xAC 0xED (base64: rO0A)
JAVA_MAGIC_B64  = b"rO0A"
JAVA_MAGIC_HEX  = "aced0005"
JAVA_MAGIC_BYTES = b"\xac\xed"

# PHP serialized strings
PHP_PATTERNS = [
    re.compile(r'^a:\d+:\{'),          # array
    re.compile(r'^O:\d+:"[^"]+":'),    # object
    re.compile(r'^s:\d+:"'),           # string
    re.compile(r'^i:\d+;'),            # integer
    re.compile(r'^b:[01];'),           # boolean
    re.compile(r'^C:\d+:"[^"]+":'),    # custom object
]

# Python pickle: starts with 0x80 0x02/0x04/0x05 (protocol 2, 4, or 5)
PICKLE_MAGIC_BYTES = [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"]

# .NET ViewState: base64 decoded starts with 0xFF 0x01
VIEWSTATE_MAGIC = b"\xff\x01"


# ─── Detection helpers ────────────────────────────────────────────────────────

def try_b64_decode(value: str) -> bytes | None:
    """Attempt base64 decoding with padding fix."""
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded)
    except Exception:
        try:
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return None


def detect_java(value: str, raw_bytes: bytes | None = None) -> bool:
    if JAVA_MAGIC_B64 in value.encode():
        return True
    if JAVA_MAGIC_HEX in value.lower():
        return True
    decoded = try_b64_decode(value)
    if decoded and decoded[:2] == JAVA_MAGIC_BYTES:
        return True
    if raw_bytes and raw_bytes[:2] == JAVA_MAGIC_BYTES:
        return True
    return False


def detect_php(value: str) -> bool:
    for pat in PHP_PATTERNS:
        if pat.match(value):
            return True
    # URL-decoded check
    try:
        decoded = urllib.parse.unquote(value)
        for pat in PHP_PATTERNS:
            if pat.match(decoded):
                return True
    except Exception:
        pass
    return False


def detect_pickle(value: str) -> bool:
    decoded = try_b64_decode(value)
    if decoded:
        for magic in PICKLE_MAGIC_BYTES:
            if decoded[:2] == magic:
                return True
    return False


def detect_viewstate(value: str, param_name: str = "") -> bool:
    if param_name.lower() in ("__viewstate", "viewstate", "__viewstategenerator"):
        decoded = try_b64_decode(value)
        if decoded and decoded[:2] == VIEWSTATE_MAGIC:
            return True
    return False


def detect_xstream(value: str) -> bool:
    """XStream XML serialization markers."""
    markers = ["<java.util", "<com.", "<org.apache", "<linked-hash-map", "<entry>"]
    val_lower = value.lower()
    return any(m in val_lower for m in markers)


def detect_rubymarshal(value: str) -> bool:
    """Ruby Marshal: base64 decoded starts with 0x04 0x08."""
    decoded = try_b64_decode(value)
    if decoded and len(decoded) >= 2 and decoded[0] == 0x04 and decoded[1] == 0x08:
        return True
    return False


def analyze_value(source: str, key: str, value: str):
    """Run all detectors against a key/value pair."""
    findings = []

    if detect_java(value):
        findings.append(("Java serialized object", "CRITICAL",
                          "Java 0xACED magic bytes (rO0A base64) detected — potential ysoserial target"))
    if detect_php(value):
        findings.append(("PHP serialized object", "HIGH",
                          f"PHP serialize() pattern in {source}:{key}"))
    if detect_pickle(value):
        findings.append(("Python pickle object", "CRITICAL",
                          "Python pickle protocol magic bytes — RCE risk"))
    if detect_viewstate(value, key):
        findings.append((".NET ViewState", "MEDIUM",
                          f"__VIEWSTATE in {source}:{key} — check MAC validation"))
    if detect_xstream(value):
        findings.append(("XStream XML serialization", "HIGH",
                          "XStream XML markers — potential CVE-2021-39144 target"))
    if detect_rubymarshal(value):
        findings.append(("Ruby Marshal object", "HIGH",
                          "Ruby Marshal 0x0408 magic bytes"))

    for name, severity, detail in findings:
        color = RED if severity in ("CRITICAL", "HIGH") else YELLOW
        print(f"  {color}[{severity}]{RESET} {name}")
        print(f"    {DIM}Source: {source}, Key: {key}{RESET}")
        print(f"    {DIM}{detail}{RESET}")
        print(f"    {DIM}Value (first 80): {value[:80]}{RESET}")
        FINDINGS.append({
            "name": name, "severity": severity, "source": source,
            "key": key, "value": value[:120], "detail": detail
        })


def scan_cookies(cookie_header: str):
    """Parse and scan cookie values."""
    print(f"\n{BOLD}[2] Cookie Analysis{RESET}")
    if not cookie_header:
        print(f"  {DIM}No Set-Cookie headers found{RESET}")
        return
    for cookie in cookie_header.split(";"):
        if "=" in cookie:
            k, _, v = cookie.partition("=")
            k, v = k.strip(), v.strip()
            print(f"  {DIM}Cookie: {k} = {v[:60]}{'...' if len(v)>60 else ''}{RESET}")
            analyze_value("cookie", k, v)


def scan_body(body: str, content_type: str):
    """Scan response body for serialized objects."""
    print(f"\n{BOLD}[3] Response Body Analysis{RESET}")
    print(f"  {DIM}Content-Type: {content_type}{RESET}")

    # Check whole body
    if detect_java(body):
        print(f"  {RED}[CRITICAL]{RESET} Java serialized bytes in response body")
        FINDINGS.append({"name": "java-in-body", "severity": "CRITICAL",
                          "source": "body", "key": "body", "value": body[:120],
                          "detail": "Java serialized object in response body"})

    # Look for base64-like values in JSON
    if "application/json" in content_type:
        try:
            obj = json.loads(body)
            _scan_json(obj, "json-body")
        except Exception:
            pass

    # HTML form: look for __VIEWSTATE
    vs_match = re.search(r'name="(__VIEWSTATE[^"]*)"[^>]*value="([^"]*)"', body)
    if vs_match:
        param, value = vs_match.group(1), vs_match.group(2)
        print(f"  {YELLOW}[INFO]{RESET} Found {param} in HTML form")
        analyze_value("html-form", param, value)


def _scan_json(obj, source: str, depth: int = 0):
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and len(v) > 20:
                analyze_value(source, k, v)
            elif isinstance(v, (dict, list)):
                _scan_json(v, source, depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_json(item, f"{source}[{i}]", depth + 1)


def scan_headers(headers: dict):
    """Scan response headers for serialized data."""
    print(f"\n{BOLD}[4] Response Header Analysis{RESET}")
    interesting = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("set-cookie", "x-auth-token", "authorization", "x-session", "x-user-data"):
            interesting[k] = v
    if not interesting:
        print(f"  {DIM}No suspicious headers found{RESET}")
        return
    for k, v in interesting.items():
        print(f"  {DIM}{k}: {v[:80]}{RESET}")
        analyze_value("response-header", k, v)


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, cookie: str = "", timeout: int = 10) -> tuple[int, dict, str]:
    hdrs = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if cookie:
        hdrs["Cookie"] = cookie
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode(errors="replace")
            resp_headers = {}
            for k in r.headers:
                resp_headers[k] = r.headers[k]
            return r.status, resp_headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        resp_headers = {}
        for k in e.headers:
            resp_headers[k] = e.headers[k]
        return e.code, resp_headers, body
    except Exception as e:
        return 0, {}, str(e)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Insecure deserialization detector")
    parser.add_argument("--url",     required=True, help="Target URL to scan")
    parser.add_argument("--cookie",  default="", help="Optional cookie string to send")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be analyzed without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   Deserialization Scanner            ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target : {CYAN}{args.url}{RESET}")

    print(f"\n{BOLD}[1] Signature Library{RESET}")
    sigs = [
        ("Java", "base64(rO0A...) or 0xACED0005"),
        ("PHP", "a:N:{...} / O:N:\"ClassName\":"),
        ("Python pickle", "base64(\\x80\\x02|\\x04|\\x05...)"),
        (".NET ViewState", "__VIEWSTATE base64(\\xff\\x01...)"),
        ("XStream XML", "<java.util...> or <com....>"),
        ("Ruby Marshal", "base64(\\x04\\x08...)"),
    ]
    for lang, sig in sigs:
        print(f"  {DIM}{lang:18s} {sig}{RESET}")

    if args.dry_run:
        print(f"\n  {YELLOW}[DRY-RUN]{RESET} Would GET {args.url} and analyze response")
        print(f"  Would check: cookies, response body, headers")
        return

    time.sleep(1.0 / args.rate)
    status, headers, body = http_get(args.url, args.cookie)

    if status == 0:
        print(f"\n{RED}[ERROR]{RESET} Could not reach {args.url}: {body}")
        sys.exit(1)

    print(f"\n  {DIM}HTTP {status} — {len(body)} bytes{RESET}")

    # Gather all Set-Cookie values
    cookie_vals = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            cookie_vals.append(v)
    scan_cookies("; ".join(cookie_vals))

    ct = headers.get("Content-Type", headers.get("content-type", ""))
    scan_body(body, ct)
    scan_headers(headers)

    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Findings : {len(FINDINGS)}")
    if FINDINGS:
        critical = [f for f in FINDINGS if f["severity"] == "CRITICAL"]
        high     = [f for f in FINDINGS if f["severity"] == "HIGH"]
        if critical:
            print(f"  {RED}CRITICAL : {len(critical)}{RESET}")
        if high:
            print(f"  {RED}HIGH     : {len(high)}{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "status": status, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
