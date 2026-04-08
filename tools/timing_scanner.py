#!/usr/bin/env python3
"""
timing_scanner.py — Response timing analysis for username enumeration and HMAC attacks.

Measures response time differentials to detect user enumeration and timing side-channels.
Uses statistical analysis (mean, stddev, outlier detection) over multiple samples.

Usage:
  python3 tools/timing_scanner.py --url https://app.example.com/login --param username
  python3 tools/timing_scanner.py --url https://app.example.com/login --param username --wordlist users.txt
  python3 tools/timing_scanner.py --url https://app.example.com/login --param username --samples 20 --dry-run
  python3 tools/timing_scanner.py --url https://app.example.com/login --param username --json
"""

import argparse
import json
import math
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

# Built-in test wordlist — mix of likely-valid and clearly-invalid usernames
BUILTIN_WORDLIST = [
    "admin", "administrator", "root", "user", "test", "guest",
    "support", "info", "help", "demo", "api",
    "nonexistent_xyz_123", "zzz_no_such_user_abc", "totally_invalid_8675309",
]


# ─── Statistics helpers ───────────────────────────────────────────────────────

def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def is_outlier(value: float, all_values: list[float], threshold: float = 2.0) -> bool:
    """Return True if value is more than threshold standard deviations from mean."""
    m = mean(all_values)
    s = stddev(all_values)
    if s == 0:
        return False
    return abs(value - m) / s > threshold


def confidence_interval(values: list[float], z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval."""
    m = mean(values)
    s = stddev(values)
    margin = z * s / math.sqrt(len(values)) if values else 0
    return (m - margin, m + margin)


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def timed_request(url: str, method: str, body: dict,
                   timeout: int = 15) -> tuple[int, float]:
    """Send request and return (status_code, elapsed_seconds)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        },
        method=method,
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            return r.status, time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        e.read()
        return e.code, time.perf_counter() - t0
    except Exception:
        return 0, time.perf_counter() - t0


def record(test: str, result: str, detail: str, severity: str = "MEDIUM"):
    FINDINGS.append({"test": test, "result": result, "detail": detail, "severity": severity})
    color = RED if result == "VULNERABLE" else (YELLOW if result == "INTERESTING" else GREEN)
    print(f"\n  {color}[{result}]{RESET} {test}")
    if detail:
        print(f"    {DIM}{detail}{RESET}")


# ─── Test Cases ───────────────────────────────────────────────────────────────

def measure_user(url: str, param: str, username: str,
                  password: str, samples: int, method: str) -> list[float]:
    """Take N samples for a username and return response times."""
    times = []
    body = {param: username, "password": password}
    for _ in range(samples):
        _, elapsed = timed_request(url, method, body)
        times.append(elapsed * 1000)  # convert to ms
    return times


def test_username_enumeration(url: str, param: str, wordlist: list[str],
                                samples: int, method: str,
                                rate: float, dry_run: bool):
    print(f"\n{BOLD}[1] Username Enumeration via Timing{RESET}")
    print(f"  {DIM}Testing {len(wordlist)} usernames × {samples} samples{RESET}")
    print(f"  {DIM}Threshold: outlier if >2σ from mean response time{RESET}")

    if dry_run:
        for u in wordlist:
            body = {param: u, "password": "Password123!"}
            print(f"  {CYAN}[DRY-RUN]{RESET} Would measure {samples}× {method} {url}")
            print(f"    {DIM}Body: {json.dumps(body)}{RESET}")
        return

    results = {}  # username → [times]
    for username in wordlist:
        print(f"  {DIM}Measuring: {username:30s}{RESET}", end="\r")
        times = measure_user(url, param, username, "Password123!", samples, method)
        time.sleep(1.0 / rate)
        results[username] = times

    print()
    # Aggregate stats
    all_means = {u: mean(t) for u, t in results.items()}
    all_times  = [v for times in results.values() for v in times]

    print(f"\n  {'Username':30s} {'Mean(ms)':>10} {'StdDev':>8} {'Outlier?':>10}")
    print(f"  {'─'*62}")

    outliers = []
    for username, times in sorted(results.items(), key=lambda x: mean(x[1]), reverse=True):
        m   = mean(times)
        s   = stddev(times)
        lo, hi = confidence_interval(times)
        out = is_outlier(m, list(all_means.values()))
        flag = f"{RED}YES{RESET}" if out else f"{GREEN}no{RESET}"
        print(f"  {username:30s} {m:>10.1f} {s:>8.1f} {flag}")
        if out:
            outliers.append((username, m, s))

    if outliers:
        detail_parts = []
        for u, m, s in outliers:
            detail_parts.append(f"{u} mean={m:.1f}ms")
        record("username-timing", "VULNERABLE",
               f"Outlier(s) detected: {', '.join(detail_parts)}")
        print(f"\n  {RED}[!]{RESET} Likely valid usernames (timing outliers): "
              f"{', '.join(u for u, _, _ in outliers)}")
    else:
        record("username-timing", "BLOCKED",
               "No statistically significant timing difference detected")


def test_hmac_timing(url: str, param: str, samples: int,
                      method: str, rate: float, dry_run: bool):
    """
    HMAC timing: send strings that differ only in the last character.
    Server computes HMAC comparison — early exit leaks timing.
    """
    print(f"\n{BOLD}[2] HMAC / Secret Comparison Timing{RESET}")
    print(f"  {DIM}Sending strings with shared prefix, differing last byte{RESET}")

    base = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    candidates = [
        ("all-A",          base),
        ("last-B",         base[:-1] + "B"),
        ("last-Z",         base[:-1] + "Z"),
        ("first-diff",     "B" + base[1:]),
        ("empty",          ""),
        ("numeric",        "0" * len(base)),
    ]

    if dry_run:
        for name, value in candidates:
            print(f"  {CYAN}[DRY-RUN]{RESET} {name}: {value[:40]}...")
        return

    results = {}
    for name, value in candidates:
        body = {param: value, "password": "test"}
        times = []
        for _ in range(samples):
            _, elapsed = timed_request(url, method, body)
            times.append(elapsed * 1000)
            time.sleep(1.0 / rate)
        results[name] = times

    print(f"\n  {'Candidate':20s} {'Mean(ms)':>10} {'StdDev':>8} {'95% CI'}")
    print(f"  {'─'*60}")
    all_means = {n: mean(t) for n, t in results.items()}
    for name, times in sorted(results.items(), key=lambda x: mean(x[1]), reverse=True):
        m  = mean(times)
        s  = stddev(times)
        lo, hi = confidence_interval(times)
        print(f"  {name:20s} {m:>10.2f} {s:>8.2f} [{lo:.2f}, {hi:.2f}]")

    # Check for outlier timing
    outlier_names = [n for n, m in all_means.items() if is_outlier(m, list(all_means.values()))]
    if outlier_names:
        record("hmac-timing", "INTERESTING",
               f"Timing outliers in HMAC comparison: {', '.join(outlier_names)}")
    else:
        record("hmac-timing", "BLOCKED", "No significant HMAC timing difference")


def test_password_timing(url: str, param: str, samples: int,
                          method: str, rate: float, dry_run: bool):
    """Test password comparison timing for a known-valid username."""
    print(f"\n{BOLD}[3] Password Comparison Timing (valid vs invalid user){RESET}")
    print(f"  {DIM}Compare timing for existing vs non-existing user with same password{RESET}")

    test_cases = [
        # 'admin' is a common username assumed to exist — timing diff vs truly invalid user
        ("common-username",       "admin",                   "WrongPassword!1"),
        ("invalid-user",          "nonexistent_xyz_8675309", "WrongPassword!1"),
        ("common-username-short", "admin",                   "a"),
        ("invalid-short",         "nonexistent_xyz_8675309", "a"),
    ]

    if dry_run:
        for name, user, pwd in test_cases:
            print(f"  {CYAN}[DRY-RUN]{RESET} {name}: user={user}, pwd={pwd}")
        return

    results = {}
    for name, user, pwd in test_cases:
        body = {param: user, "password": pwd}
        times = []
        for _ in range(samples):
            _, elapsed = timed_request(url, method, body)
            times.append(elapsed * 1000)
            time.sleep(1.0 / rate)
        results[name] = times
        print(f"  {DIM}{name:30s} mean={mean(times):.1f}ms{RESET}")

    # Compare valid-ish vs invalid
    valid_mean   = mean(results.get("common-username", [0]))
    invalid_mean = mean(results.get("invalid-user",    [0]))
    diff = abs(valid_mean - invalid_mean)

    if diff > 50:  # >50ms difference is suspicious
        record("password-timing", "VULNERABLE",
               f"Valid user mean={valid_mean:.1f}ms vs invalid={invalid_mean:.1f}ms "
               f"(diff={diff:.1f}ms > 50ms threshold)")
    elif diff > 20:
        record("password-timing", "INTERESTING",
               f"Valid={valid_mean:.1f}ms, invalid={invalid_mean:.1f}ms (diff={diff:.1f}ms)")
    else:
        record("password-timing", "BLOCKED",
               f"Diff={diff:.1f}ms — below 20ms threshold")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Timing-based vulnerability scanner")
    parser.add_argument("--url",       required=True, help="Target endpoint URL")
    parser.add_argument("--param",     required=True, help="Username/identifier parameter name")
    parser.add_argument("--method",    default="POST",
                        choices=["GET", "POST", "PUT"],
                        help="HTTP method (default: POST)")
    parser.add_argument("--samples",   type=int, default=10,
                        help="Samples per username (default: 10)")
    parser.add_argument("--wordlist",  default="",
                        help="Path to username wordlist (one per line)")
    parser.add_argument("--rate",      type=float, default=1.0, metavar="REQ/S",
                        help="Request rate limit in req/sec (default: 1.0)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Show what would be tested without sending requests")
    parser.add_argument("--json",      action="store_true", dest="json_output",
                        help="Output results as JSON")
    args = parser.parse_args()

    # Load wordlist
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{RED}[ERROR]{RESET} Wordlist not found: {args.wordlist}")
            sys.exit(1)
    else:
        wordlist = BUILTIN_WORDLIST

    print(f"\n{BOLD}{BLUE}╔══════════════════════════════════════╗")
    print(f"║   Timing Attack Scanner              ║")
    print(f"╚══════════════════════════════════════╝{RESET}")
    print(f"  Target    : {CYAN}{args.url}{RESET}")
    print(f"  Param     : {args.param}")
    print(f"  Samples   : {args.samples}")
    print(f"  Wordlist  : {len(wordlist)} entries")
    print(f"  Rate      : {args.rate} req/sec")
    if args.dry_run:
        print(f"  Mode      : {YELLOW}DRY-RUN (no requests sent){RESET}")

    total_reqs = len(wordlist) * args.samples
    print(f"\n  {DIM}Estimated requests: ~{total_reqs} (username enum) "
          f"+ {6 * args.samples} (HMAC) + {4 * args.samples} (password timing){RESET}")

    test_username_enumeration(args.url, args.param, wordlist,
                               args.samples, args.method, args.rate, args.dry_run)
    test_hmac_timing(args.url, args.param, args.samples,
                      args.method, args.rate, args.dry_run)
    test_password_timing(args.url, args.param, args.samples,
                          args.method, args.rate, args.dry_run)

    vulns = [f for f in FINDINGS if f["result"] in ("VULNERABLE", "INTERESTING")]
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"  Findings  : {len(vulns)}")
    for f in vulns:
        color = RED if f["result"] == "VULNERABLE" else YELLOW
        print(f"    {color}→{RESET} {f['test']}: {f['detail']}")

    if args.json_output:
        print(json.dumps({"url": args.url, "param": args.param, "findings": FINDINGS}, indent=2))


if __name__ == "__main__":
    main()
