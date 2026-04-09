#!/usr/bin/env python3
"""
Bug Bounty Hunt Orchestrator
Main script that chains target selection, recon, scanning, and reporting.
Includes exotic vuln scanning (CORS, SSTI, open redirect, and 14 more).

Usage:
    python3 hunt.py                         # Full pipeline: select targets + hunt
    python3 hunt.py --target <domain>       # Hunt a specific target
    python3 hunt.py --quick --target <domain>  # Quick scan mode
    python3 hunt.py --recon-only --target <domain>  # Only run recon
    python3 hunt.py --scan-only --target <domain>   # Only run vuln scanner (requires prior recon)
    python3 hunt.py --exotic --target <domain>      # + exotic scanners (core 3: cors, ssti, open_redirect)
    python3 hunt.py --exotic quick --target <domain> # + 6 exotic scanners
    python3 hunt.py --exotic deep --target <domain>  # + all 17 exotic scanners
    python3 hunt.py --exotic off --target <domain>   # skip exotic phase
    python3 hunt.py --status                # Show current progress
    python3 hunt.py --setup-wordlists       # Download common wordlists
    python3 hunt.py --cve-hunt --target <domain>   # Run CVE hunter
    python3 hunt.py --zero-day --target <domain>   # Run zero-day fuzzer
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(TOOLS_DIR)
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# Output root — configurable via BBH_OUTPUT_DIR, defaults to ~/bug-bounty-outputs
OUTPUT_ROOT = os.environ.get("BBH_OUTPUT_DIR", str(Path.home() / "bug-bounty-outputs"))
RECON_DIR    = os.path.join(OUTPUT_ROOT, "recon")
FINDINGS_DIR = os.path.join(OUTPUT_ROOT, "findings")
REPORTS_DIR  = os.path.join(OUTPUT_ROOT, "reports")

# Colors
GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(level, msg):
    colors = {"ok": GREEN, "err": RED, "warn": YELLOW, "info": CYAN}
    symbols = {"ok": "+", "err": "-", "warn": "!", "info": "*"}
    print(f"{colors.get(level, '')}{BOLD}[{symbols.get(level, '*')}]{NC} {msg}")


def run_cmd(cmd, cwd=None, timeout=600):
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            cwd=cwd, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def check_tools():
    """Check which tools are installed."""
    tools = ["subfinder", "httpx", "nuclei", "ffuf", "nmap", "amass", "gau", "dalfox", "subjack"]
    installed = []
    missing = []

    for tool in tools:
        success, _ = run_cmd(f"command -v {tool}")
        if success:
            installed.append(tool)
        else:
            missing.append(tool)

    return installed, missing


def setup_wordlists():
    """Download common wordlists for fuzzing."""
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    wordlists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-medium-dirs.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
        "params.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
    }

    for name, url in wordlists.items():
        filepath = os.path.join(WORDLIST_DIR, name)
        if os.path.exists(filepath):
            log("ok", f"Wordlist exists: {name}")
            continue

        log("info", f"Downloading {name}...")
        success, output = run_cmd(f'curl -sL "{url}" -o "{filepath}"')
        if success and os.path.getsize(filepath) > 100:
            lines = sum(1 for _ in open(filepath))
            log("ok", f"Downloaded {name} ({lines} entries)")
        else:
            log("err", f"Failed to download {name}")

    log("ok", f"Wordlists ready in {WORDLIST_DIR}")


def select_targets(top_n=10):
    """Run target selector."""
    log("info", "Running target selector...")
    script = os.path.join(TOOLS_DIR, "target_selector.py")
    success, output = run_cmd(
        f'python3 "{script}" --top {top_n}',
        timeout=60
    )
    print(output)

    if not success:
        log("err", "Target selection failed")
        return []

    # Load selected targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        return data.get("targets", [])

    return []


def _resolve_recon_dir(domain: str) -> str:
    """Return the recon output directory for *domain* (not guaranteed to exist)."""
    return os.path.join(RECON_DIR, domain)


def _resolve_findings_dir(domain: str, create: bool = False) -> str:
    """Return the findings output directory for *domain*."""
    path = os.path.join(FINDINGS_DIR, domain)
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _activate_recon_session(domain: str, requested_session_id: str = "latest",
                            create: bool = True) -> tuple[str, str]:
    """Return (session_id, recon_dir) for *domain*.  Creates the directory when *create* is True."""
    rdir = _resolve_recon_dir(domain)
    if create:
        os.makedirs(rdir, exist_ok=True)
    session_id = requested_session_id if requested_session_id != "latest" else "default"
    return session_id, rdir


def run_recon(domain, quick=False):
    """Run recon engine on a domain."""
    log("info", f"Running recon on {domain}...")
    script = os.path.join(TOOLS_DIR, "recon_engine.sh")
    quick_flag = "--quick" if quick else ""

    # Run with live output
    ok = False
    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{domain}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)  # 30 min timeout
        ok = proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Recon timed out for {domain}")
        ok = False

    # Normalize recon output so brain.py reads consistent format (TODO-5 follow-through)
    try:
        sys.path.insert(0, TOOLS_DIR)
        from recon_adapter import ReconAdapter
        adapter = ReconAdapter(_resolve_recon_dir(domain))
        adapter.normalize()
    except Exception as _norm_err:
        log("warn", f"ReconAdapter.normalize() skipped: {_norm_err}")

    return ok


def check_cicd_results(domain):
    """Check and surface CI/CD scan results from recon Phase 8."""
    cicd_dir = os.path.join(RECON_DIR, domain, "cicd")
    if not os.path.isdir(cicd_dir):
        return
    for root, dirs, files in os.walk(cicd_dir):
        for f in files:
            if f == "summary.txt":
                summary_path = os.path.join(root, f)
                with open(summary_path) as sf:
                    content = sf.read()
                if "Total findings: 0" not in content:
                    log("warn", f"CI/CD findings detected — review: {summary_path}")


def run_vuln_scan(domain, quick=False):
    """Run vulnerability scanner on recon results."""
    recon_dir = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir):
        log("err", f"No recon data found for {domain}. Run recon first.")
        return False

    log("info", f"Running vulnerability scanner on {domain}...")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    quick_flag = "--quick" if quick else ""

    try:
        proc = subprocess.Popen(
            f'bash "{script}" "{recon_dir}" {quick_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=1800)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Vulnerability scan timed out for {domain}")
        return False


def _run_scanner(scanner_file: str, args_str: str, domain: str, category: str,
                 timeout: int = 300) -> bool:
    """Helper: run a scanner script and write output to findings dir."""
    scanner_path = os.path.join(TOOLS_DIR, scanner_file)
    if not os.path.exists(scanner_path):
        log("warn", f"Scanner not found: {scanner_file}")
        return False
    out_dir = os.path.join(FINDINGS_DIR, domain, category)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{scanner_file.replace('.py', '')}_results.json")
    cmd = f'python3 "{scanner_path}" {args_str} > "{out_file}" 2>&1'
    ok, _ = run_cmd(cmd, timeout=timeout)
    return ok


def run_js_analysis(domain: str) -> bool:
    """Download and analyse JavaScript files discovered during recon."""
    target_url = f"https://{domain}"
    return _run_scanner("xss_scanner.py", f'--target "{target_url}" --js-only --json', domain, "js")


def run_secret_hunt(domain: str) -> bool:
    """Scan for leaked secrets in JS files and public repos."""
    target_url = f"https://{domain}"
    return _run_scanner("xss_scanner.py", f'--target "{target_url}" --secrets --json', domain, "secrets")


def run_param_discovery(domain: str) -> bool:
    """Brute-force GET URL parameters on all live hosts."""
    recon_dir_path = os.path.join(RECON_DIR, domain)
    if not os.path.isdir(recon_dir_path):
        return False
    out_dir = os.path.join(FINDINGS_DIR, domain, "params")
    os.makedirs(out_dir, exist_ok=True)
    hosts_file = os.path.join(recon_dir_path, "live", "httpx_full.txt")
    if not os.path.isfile(hosts_file):
        hosts_file = os.path.join(recon_dir_path, "httpx_full.txt")
    if not os.path.isfile(hosts_file):
        return False
    out_file = os.path.join(out_dir, "params_discovered.txt")
    cmd = f'cat "{hosts_file}" | python3 -m arjun --stdin -oJ "{out_file}" 2>&1 || true'
    ok, _ = run_cmd(cmd, timeout=600)
    return ok


def run_post_param_discovery(domain: str, cookies: str = "") -> bool:
    """Discover POST form endpoints and parameters."""
    target_url = f"https://{domain}"
    cookie_arg = f'--cookie "{cookies}"' if cookies else ""
    return _run_scanner("sqli_scanner.py",
                        f'--target "{target_url}" {cookie_arg} --post --json',
                        domain, "params", timeout=600)


def run_api_fuzz(domain: str) -> bool:
    """Fuzz API endpoints for IDOR, auth bypass, and privilege escalation."""
    target_url = f"https://{domain}"
    return _run_scanner("h1_idor_scanner.py", f'--target "{target_url}" --json', domain, "idor")


def run_cors_check(domain: str) -> bool:
    """Test live hosts for CORS misconfigurations."""
    target_url = f"https://{domain}"
    return _run_scanner("cors_scanner.py", f'--target "{target_url}" --json --rate 1.0', domain, "cors")


def run_cms_exploit(domain: str) -> bool:
    """Run CMS-specific exploit checks (Drupal, WordPress, Joomla, Magento)."""
    recon_dir_path = os.path.join(RECON_DIR, domain)
    out_dir = os.path.join(FINDINGS_DIR, domain, "cms")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "cms_results.txt")
    script = os.path.join(TOOLS_DIR, "vuln_scanner.sh")
    cmd = f'bash "{script}" --cms-only "{recon_dir_path}" 2>&1 || true'
    ok, output = run_cmd(cmd, timeout=300)
    Path(out_file).write_text(output)
    return ok


def run_rce_scan(domain: str) -> bool:
    """Scan for Remote Code Execution vectors (Log4Shell, Tomcat PUT, JBoss, SSTI)."""
    target_url = f"https://{domain}"
    return _run_scanner("ssti_scanner.py", f'--target "{target_url}" --json --rate 1.0', domain, "rce")


def run_sqlmap_targeted(domain: str) -> bool:
    """Run sqlmap against parameterized GET URLs found in recon."""
    target_url = f"https://{domain}"
    return _run_scanner("sqli_scanner.py",
                        f'--target "{target_url}" --sqlmap --json',
                        domain, "sqli", timeout=900)


def run_sqlmap_request_file(request_file: str, domain: str = "",
                             level: int = 5, risk: int = 3) -> bool:
    """Run sqlmap against a specific raw HTTP request file."""
    out_dir = os.path.join(FINDINGS_DIR, domain or "unknown", "sqlmap")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "sqlmap_results.txt")
    cmd = (f'sqlmap -r "{request_file}" --level={level} --risk={risk} '
           f'--batch --output-dir="{out_dir}" 2>&1 | tee "{out_file}"')
    ok, _ = run_cmd(cmd, timeout=1200)
    return ok


def run_jwt_audit(domain: str) -> bool:
    """Audit JWT tokens found in recon artifacts."""
    target_url = f"https://{domain}"
    return _run_scanner("jwt_scanner.py", f'--target "{target_url}" --json', domain, "jwt")


def run_ssti_scan(domain: str) -> bool:
    """Detect SSTI injection (Jinja2, Twig, Freemarker, EJS, Pug)."""
    target_url = f"https://{domain}"
    return _run_scanner("ssti_scanner.py", f'--target "{target_url}" --json --rate 1.0', domain, "rce")


def run_open_redirect_scan(domain: str) -> bool:
    """Test for open redirects — critical for OAuth token theft chains."""
    target_url = f"https://{domain}"
    return _run_scanner("open_redirect_scanner.py",
                        f'--target "{target_url}" --json --rate 1.0',
                        domain, "redirects")


def run_proto_pollution_scan(domain: str) -> bool:
    """Test for prototype pollution (Node.js stacks)."""
    target_url = f"https://{domain}"
    return _run_scanner("proto_pollution_scanner.py",
                        f'--url "{target_url}" --json',
                        domain, "proto_pollution")


def run_xxe_scan(domain: str) -> bool:
    """Test XML-accepting endpoints for XXE injection."""
    target_url = f"https://{domain}"
    return _run_scanner("xxe_scanner.py", f'--url "{target_url}" --json', domain, "xxe")


def run_websocket_scan(domain: str) -> bool:
    """Test WebSocket endpoints for injection and auth issues."""
    ws_url = f"wss://{domain}"
    return _run_scanner("websocket_scanner.py", f'--url "{ws_url}" --json', domain, "websocket")


def run_deserial_scan(domain: str) -> bool:
    """Test Java/PHP/.NET endpoints for deserialization vulnerabilities."""
    target_url = f"https://{domain}"
    return _run_scanner("deserial_scanner.py", f'--url "{target_url}" --json', domain, "deserial")


def generate_reports(domain):
    """Generate reports for findings."""
    findings_dir = os.path.join(FINDINGS_DIR, domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0

    log("info", f"Generating reports for {domain}...")
    script = os.path.join(TOOLS_DIR, "report_generator.py")
    success, output = run_cmd(f'python3 "{script}" "{findings_dir}"')
    print(output)

    # Count generated reports
    report_dir = os.path.join(REPORTS_DIR, domain)
    if os.path.isdir(report_dir):
        return len([f for f in os.listdir(report_dir) if f.endswith(".md") and f != "SUMMARY.md"])
    return 0


def show_status():
    """Show current pipeline status."""
    print(f"\n{BOLD}{'='*50}{NC}")
    print(f"{BOLD}  Bug Bounty Pipeline Status{NC}")
    print(f"{BOLD}{'='*50}{NC}\n")

    # Check tools
    installed, missing = check_tools()
    print(f"  Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        print(f"  Missing: {', '.join(missing)}")

    # Check targets
    targets_file = os.path.join(TARGETS_DIR, "selected_targets.json")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            data = json.load(f)
        print(f"  Selected targets: {data.get('total_targets', 0)}")
    else:
        print("  Selected targets: None (run target selector first)")

    # Check recon results
    if os.path.isdir(RECON_DIR):
        recon_targets = [d for d in os.listdir(RECON_DIR) if os.path.isdir(os.path.join(RECON_DIR, d))]
        print(f"  Recon completed: {len(recon_targets)} targets")
        for t in recon_targets:
            subs_file = os.path.join(RECON_DIR, t, "subdomains", "all.txt")
            live_file = os.path.join(RECON_DIR, t, "live", "urls.txt")
            subs = sum(1 for _ in open(subs_file)) if os.path.exists(subs_file) else 0
            live = sum(1 for _ in open(live_file)) if os.path.exists(live_file) else 0
            print(f"    - {t}: {subs} subdomains, {live} live hosts")

    # Check findings
    if os.path.isdir(FINDINGS_DIR):
        finding_targets = [d for d in os.listdir(FINDINGS_DIR) if os.path.isdir(os.path.join(FINDINGS_DIR, d))]
        print(f"  Scanned targets: {len(finding_targets)}")
        for t in finding_targets:
            summary = os.path.join(FINDINGS_DIR, t, "summary.txt")
            if os.path.exists(summary):
                with open(summary) as f:
                    content = f.read()
                total_match = content.split("TOTAL FINDINGS:")
                if len(total_match) > 1:
                    total = total_match[1].strip().split("\n")[0].strip()
                    print(f"    - {t}: {total} findings")

    # Check reports
    if os.path.isdir(REPORTS_DIR):
        report_targets = [d for d in os.listdir(REPORTS_DIR) if os.path.isdir(os.path.join(REPORTS_DIR, d))]
        print(f"  Reports generated: {len(report_targets)} targets")
        for t in report_targets:
            reports = [f for f in os.listdir(os.path.join(REPORTS_DIR, t)) if f.endswith(".md") and f != "SUMMARY.md"]
            print(f"    - {t}: {len(reports)} reports")

    print(f"\n{'='*50}\n")


def print_dashboard(results):
    """Print final summary dashboard."""
    print(f"\n{BOLD}{'='*60}{NC}")
    print(f"{BOLD}  HUNT COMPLETE — Summary Dashboard{NC}")
    print(f"{BOLD}{'='*60}{NC}\n")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    total_findings = 0
    total_reports = 0

    for r in results:
        status_icon = f"{GREEN}OK{NC}" if r["success"] else f"{RED}FAIL{NC}"
        print(f"  [{status_icon}] {r['domain']}")
        print(f"       Recon: {'Done' if r.get('recon') else 'Skipped'} | "
              f"Scan: {'Done' if r.get('scan') else 'Skipped'} | "
              f"Reports: {r.get('reports', 0)}")
        total_findings += r.get("findings", 0)
        total_reports += r.get("reports", 0)

    print(f"\n  Total reports generated: {total_reports}")
    print(f"\n  Reports directory: {REPORTS_DIR}/")
    print(f"\n{'='*60}")

    if total_reports > 0:
        print(f"\n  {YELLOW}Next steps:{NC}")
        print("  1. Review each report in the reports/ directory")
        print("  2. Manually verify findings before submitting")
        print("  3. Add PoC screenshots where applicable")
        print("  4. Submit via HackerOne program pages")
        print(f"\n{'='*60}\n")


def run_cve_hunt(domain):
    """Run CVE hunter on a target."""
    log("info", f"Running CVE hunter on {domain}...")
    script = os.path.join(TOOLS_DIR, "cve_hunter.py")
    recon_dir = os.path.join(RECON_DIR, domain)
    recon_flag = f'--recon-dir "{recon_dir}"' if os.path.isdir(recon_dir) else ""

    try:
        proc = subprocess.Popen(
            f'python3 "{script}" "{domain}" {recon_flag}',
            shell=True, cwd=BASE_DIR
        )
        proc.wait(timeout=600)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"CVE hunt timed out for {domain}")
        return False


def run_zero_day_fuzzer(domain, deep=False):
    """Run zero-day fuzzer on a target."""
    log("info", f"Running zero-day fuzzer on {domain}...")
    script = os.path.join(TOOLS_DIR, "zero_day_fuzzer.py")
    deep_flag = "--deep" if deep else ""

    # Check if we have recon data with live URLs
    recon_dir = os.path.join(RECON_DIR, domain)
    if os.path.isdir(recon_dir):
        cmd = f'python3 "{script}" "https://{domain}" --recon-dir "{recon_dir}" {deep_flag}'
    else:
        cmd = f'python3 "{script}" "https://{domain}" {deep_flag}'

    try:
        proc = subprocess.Popen(cmd, shell=True, cwd=BASE_DIR)
        proc.wait(timeout=900)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill()
        log("err", f"Zero-day fuzzer timed out for {domain}")
        return False


def run_exotic_scan(domain, profile="core", quick=False):
    """Run exotic vulnerability scanners on a target.

    profile: "core" (cors+ssti+open_redirect), "quick" (core + 3 more), "deep" (all 17)
    """
    target_url = f"https://{domain}"
    recon_dir = os.path.join(RECON_DIR, domain)
    findings_dir = os.path.join(FINDINGS_DIR, "exotic", domain)
    os.makedirs(findings_dir, exist_ok=True)

    log("info", f"Running exotic scanners on {domain} [profile={profile}]...")

    # Core 3 — always run
    core_scanners = [
        ("cors_scanner.py",          f'--target "{target_url}" --json --rate 1.0'),
        ("ssti_scanner.py",          f'--target "{target_url}" --json --rate 1.0'),
        ("open_redirect_scanner.py", f'--target "{target_url}" --json --rate 1.0'),
    ]

    # Quick extras — added on top of core 3 with --exotic quick
    quick_scanners = [
        ("jwt_scanner.py",              f'--url "{target_url}" --json'),
        ("host_header_scanner.py",      f'--url "{target_url}" --json'),
        ("dependency_confusion_scanner.py", f'--target "{domain}" --json'),
    ]

    # Full exotic suite — only with --exotic deep
    deep_scanners = [
        ("proto_pollution_scanner.py",  f'--url "{target_url}" --json'),
        ("graphql_deep_scanner.py",     f'--url "{target_url}/graphql" --json'),
        ("xxe_scanner.py",              f'--url "{target_url}" --json'),
        ("deserial_scanner.py",         f'--url "{target_url}" --json'),
        ("websocket_scanner.py",        f'--url "wss://{domain}" --json'),
        ("timing_scanner.py",           f'--url "{target_url}" --json'),
        ("postmessage_scanner.py",      f'--url "{target_url}" --json'),
        ("css_injection_scanner.py",    f'--url "{target_url}" --json'),
        ("esi_scanner.py",              f'--url "{target_url}" --json'),
        ("ssl_scanner.py",              f'--host "{domain}" --json'),
        ("dns_rebinding_tester.py",     f'--target "{target_url}" --json'),
        ("network_scanner.py",          f'--host "{domain}" --json'),
        ("crlf_scanner.py",             f'--url "{target_url}" --json'),
        ("rate_limit_tester.py",        f'--url "{target_url}" --json'),
    ]

    # Select scanners based on profile
    if profile == "core":
        scanners = core_scanners
    elif profile == "quick":
        scanners = core_scanners + quick_scanners
    elif profile == "deep":
        scanners = core_scanners + quick_scanners + deep_scanners
    else:
        log("warn", f"Unknown exotic profile '{profile}', using 'core'")
        scanners = core_scanners

    ran, failed = 0, 0
    for scanner_file, scanner_args in scanners:
        scanner_path = os.path.join(TOOLS_DIR, scanner_file)
        if not os.path.exists(scanner_path):
            log("warn", f"Scanner not found, skipping: {scanner_file}")
            continue

        scanner_name = scanner_file.replace(".py", "")
        out_file = os.path.join(findings_dir, f"{scanner_name}.json")
        cmd = f'python3 "{scanner_path}" {scanner_args} > "{out_file}" 2>&1'

        log("info", f"  [{scanner_name}]...")
        success, _ = run_cmd(cmd, timeout=120 if quick else 300)
        if success:
            ran += 1
        else:
            failed += 1
            log("warn", f"  [{scanner_name}] finished with non-zero exit (check {out_file})")

    log("ok", f"Exotic scan complete — {ran} scanners ran, {failed} had issues")
    log("info", f"Results in: {findings_dir}/")
    return ran > 0


def hunt_target(domain, quick=False, recon_only=False, scan_only=False,
                cve_hunt=False, zero_day=False, exotic_profile="core"):
    """Run the full hunt pipeline on a single target.

    Args:
        domain: Target domain to hunt.
        quick: Enable quick scan mode (fewer checks, shorter timeouts).
        recon_only: Stop after recon phase.
        scan_only: Skip recon, run vuln scan only (requires prior recon output).
        cve_hunt: Also run CVE hunter after vuln scan.
        zero_day: Also run zero-day fuzzer (high false positive rate, manual review needed).
        exotic_profile: Exotic scanner suite to run after standard vuln scan.
            'core'  — cors, ssti, open_redirect (default, ~3-5 min).
            'quick' — core + jwt, host_header, dependency_confusion (~5-10 min).
            'deep'  — all 17 exotic scanners (~20-30 min).
            'off'   — skip exotic phase entirely.
    """
    result = {"domain": domain, "success": True, "recon": False, "scan": False, "reports": 0}

    if not scan_only:
        result["recon"] = run_recon(domain, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing anyway...")

    if recon_only:
        return result

    check_cicd_results(domain)
    result["scan"] = run_vuln_scan(domain, quick=quick)

    # Exotic scanning (core 3 by default, configurable profile)
    if exotic_profile and exotic_profile != "off":
        run_exotic_scan(domain, profile=exotic_profile, quick=quick)

    # CVE hunting (only when explicitly requested)
    if cve_hunt:
        run_cve_hunt(domain)

    # Zero-day fuzzing (disabled by default — high false positive rate)
    if zero_day:
        log("warn", "Zero-day fuzzer enabled — results require manual verification")
        run_zero_day_fuzzer(domain, deep=not quick)

    result["reports"] = generate_reports(domain)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Hunt Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hunt.py                            Full pipeline (select + hunt)
  python3 hunt.py --target example.com       Hunt specific target
  python3 hunt.py --quick --target example.com  Quick scan
  python3 hunt.py --status                   Show progress
  python3 hunt.py --setup-wordlists          Download wordlists
        """
    )
    parser.add_argument("--target", type=str, help="Specific target domain to hunt")
    parser.add_argument("--quick", action="store_true", help="Quick scan mode (fewer checks)")
    parser.add_argument("--recon-only", action="store_true", help="Only run reconnaissance")
    parser.add_argument("--scan-only", action="store_true", help="Only run vulnerability scanner")
    parser.add_argument("--report-only", action="store_true", help="Only generate reports")
    parser.add_argument("--status", action="store_true", help="Show pipeline status")
    parser.add_argument("--setup-wordlists", action="store_true", help="Download wordlists")
    parser.add_argument("--cve-hunt", action="store_true", help="Run CVE hunter")
    parser.add_argument("--zero-day", action="store_true", help="Run zero-day fuzzer")
    parser.add_argument("--exotic", metavar="PROFILE", nargs="?", const="core",
                        choices=["core", "quick", "deep", "off"],
                        help="Run exotic vuln scanners: core (default), quick, deep, or off")
    parser.add_argument("--select-targets", action="store_true", help="Only run target selection")
    parser.add_argument("--top", type=int, default=10, help="Number of targets to select")
    args = parser.parse_args()

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║     Bug Bounty Automation Pipeline       ║
╚══════════════════════════════════════════╝{NC}
    """)

    # Status check
    if args.status:
        show_status()
        return

    # Setup wordlists
    if args.setup_wordlists:
        setup_wordlists()
        return

    # Check tools
    installed, missing = check_tools()
    log("info", f"Tools: {len(installed)}/{len(installed)+len(missing)} installed")
    if missing:
        log("warn", f"Missing tools: {', '.join(missing)}")
        log("warn", "Run: bash tools/install_tools.sh")

    # Target selection only
    if args.select_targets:
        select_targets(top_n=args.top)
        return

    # Report only
    if args.report_only:
        if args.target:
            generate_reports(args.target)
        else:
            if os.path.isdir(FINDINGS_DIR):
                for d in os.listdir(FINDINGS_DIR):
                    if os.path.isdir(os.path.join(FINDINGS_DIR, d)):
                        generate_reports(d)
        return

    # Hunt specific target
    if args.target:
        log("info", f"Hunting target: {args.target}")

        # Setup wordlists if missing
        if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
            setup_wordlists()

        result = hunt_target(
            args.target,
            quick=args.quick,
            recon_only=args.recon_only,
            scan_only=args.scan_only,
            cve_hunt=args.cve_hunt,
            zero_day=args.zero_day,
            exotic_profile=args.exotic or "core"
        )
        print_dashboard([result])
        return

    # Full pipeline: select targets then hunt each
    log("info", "Starting full pipeline...")

    # Setup wordlists
    if not os.path.exists(os.path.join(WORDLIST_DIR, "common.txt")):
        setup_wordlists()

    # Select targets
    targets = select_targets(top_n=args.top)
    if not targets:
        log("err", "No targets selected. Exiting.")
        sys.exit(1)

    # Hunt each target
    results = []
    for i, target in enumerate(targets):
        domains = target.get("scope_domains", [])
        if not domains:
            log("warn", f"No domains for {target.get('name', 'unknown')} — skipping")
            continue

        # Hunt the primary domain
        primary_domain = domains[0]
        log("info", f"[{i+1}/{len(targets)}] Hunting: {target.get('name', primary_domain)}")
        log("info", f"  Domain: {primary_domain}")
        log("info", f"  Program: {target.get('url', 'N/A')}")

        result = hunt_target(primary_domain, quick=args.quick, exotic_profile=args.exotic or "core")
        results.append(result)

    print_dashboard(results)


if __name__ == "__main__":
    main()
