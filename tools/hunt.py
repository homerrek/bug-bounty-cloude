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
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = BASE_DIR
TARGETS_DIR = os.path.join(BASE_DIR, "..", "targets")
WORDLIST_DIR = os.path.join(BASE_DIR, "..", "wordlists")

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
    """Run a shell command string and return (success, output).

    Uses shlex.split() to convert the command string to a list, avoiding
    shell=True. For commands that genuinely require shell features (pipes,
    redirects), callers should use subprocess directly with a validated list.
    """
    try:
        cmd_list = shlex.split(cmd) if isinstance(cmd, str) else cmd
        result = subprocess.run(
            cmd_list, shell=False, capture_output=True, text=True,
            cwd=cwd, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def run_shell_cmd(cmd: str, cwd=None, timeout=600):
    """Run a shell pipeline command and return (success, output).

    Only use this for commands that strictly require shell features such as
    pipes or redirects. The caller is responsible for sanitising all
    user-supplied values with shlex.quote() before interpolation.
    """
    try:
        result = subprocess.run(  # nosec B602 – shell required for pipeline
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
        if shutil.which(tool):
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
        success, output = run_cmd(["curl", "-sL", url, "-o", filepath])
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
        [sys.executable, script, "--top", str(top_n)],
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

    # Run with live output
    ok = False
    cmd = ["bash", script, domain]
    if quick:
        cmd.append("--quick")
    try:
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
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

    cmd = ["bash", script, recon_dir]
    if quick:
        cmd.append("--quick")
    try:
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
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
    # Use shell for output redirection; all paths and args are sanitised with shlex.quote.
    cmd = f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)} {args_str} > {shlex.quote(out_file)} 2>&1'
    ok, _ = run_shell_cmd(cmd, timeout=timeout)  # nosec B602 – shell required for redirection
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
    cmd = f'cat {shlex.quote(hosts_file)} | {shlex.quote(sys.executable)} -m arjun --stdin -oJ {shlex.quote(out_file)} 2>&1 || true'
    ok, _ = run_shell_cmd(cmd, timeout=600)  # nosec B602 – shell pipe required
    return ok


def run_post_param_discovery(domain: str, cookies: str = "") -> bool:
    """Discover POST form endpoints and parameters."""
    target_url = f"https://{domain}"
    cookie_arg = f'--cookie {shlex.quote(cookies)}' if cookies else ""
    return _run_scanner("sqli_scanner.py",
                        f'--target {shlex.quote(target_url)} {cookie_arg} --post --json',
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
    cmd = f'bash {shlex.quote(script)} --cms-only {shlex.quote(recon_dir_path)} 2>&1 || true'
    ok, output = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell pipe required
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
    # Clamp level/risk to their valid sqlmap ranges (1-5 and 1-3 respectively).
    try:
        safe_level = max(1, min(5, int(level)))
    except (ValueError, TypeError):
        safe_level = 5
    try:
        safe_risk = max(1, min(3, int(risk)))
    except (ValueError, TypeError):
        safe_risk = 3
    cmd = (f'sqlmap -r {shlex.quote(request_file)} --level={safe_level} --risk={safe_risk} '
           f'--batch --output-dir={shlex.quote(out_dir)} 2>&1 | tee {shlex.quote(out_file)}')
    ok, _ = run_shell_cmd(cmd, timeout=1200)  # nosec B602 – shell pipe (tee) required
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


def run_cache_deception_scan(domain: str) -> bool:
    """Test for web cache deception vulnerabilities."""
    target_url = f"https://{domain}"
    return _run_scanner("cache_deception_scanner.py",
                        f'--url "{target_url}" --json --rate 1.0',
                        domain, "cache_deception")


def run_pdf_ssrf_scan(domain: str) -> bool:
    """Detect HTML-to-PDF generators and test for SSRF / local file read."""
    target_url = f"https://{domain}"
    return _run_scanner("pdf_ssrf_scanner.py", f'--url "{target_url}"', domain, "pdf_ssrf")


def run_intel(domain: str, recon_dir: str) -> bool:
    """Run intel engine to fetch CVE and disclosure intel (between recon and rank steps)."""
    log("info", f"Running intel engine for {domain}...")
    script = os.path.join(TOOLS_DIR, "intel_engine.py")
    if not os.path.exists(script):
        log("warn", "intel_engine.py not found — skipping intel step")
        return False

    intel_dir = os.path.join(recon_dir, "intel")
    os.makedirs(intel_dir, exist_ok=True)
    out_file = os.path.join(intel_dir, "intel.json")

    cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(script)}'
           f' --target {shlex.quote(domain)} --json'
           f' > {shlex.quote(out_file)} 2>&1')
    ok, _ = run_shell_cmd(cmd, timeout=120)  # nosec B602 – shell redirect
    if not ok:
        log("warn", f"intel_engine.py had issues for {domain} — continuing")
    return ok


def run_h1_scanners(domain: str) -> None:
    """Run HackerOne-specific scanners in the hunt step (after vuln_scanner.sh)."""
    idor_dir = os.path.join(FINDINGS_DIR, domain, "idor")
    auth_dir = os.path.join(FINDINGS_DIR, domain, "auth_bypass")
    os.makedirs(idor_dir, exist_ok=True)
    os.makedirs(auth_dir, exist_ok=True)

    token_a = os.environ.get("H1_TOKEN_A", "")
    token_b = os.environ.get("H1_TOKEN_B", "")

    # h1_idor_scanner.py → findings/{domain}/idor/
    scanner_path = os.path.join(TOOLS_DIR, "h1_idor_scanner.py")
    if not os.path.exists(scanner_path):
        log("warn", "h1_idor_scanner.py not found — skipping")
    elif not token_a or not token_b:
        log("warn", "H1_TOKEN_A/H1_TOKEN_B not set — skipping h1_idor_scanner.py")
    else:
        out_file = os.path.join(idor_dir, "h1_idor_scanner_results.json")
        cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)}'
               f' --token-a {shlex.quote(token_a)} --token-b {shlex.quote(token_b)}'
               f' > {shlex.quote(out_file)} 2>&1')
        ok, _ = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell redirect
        if not ok:
            log("warn", "h1_idor_scanner.py finished with non-zero exit — continuing")

    # h1_mutation_idor.py → findings/{domain}/idor/
    scanner_path = os.path.join(TOOLS_DIR, "h1_mutation_idor.py")
    cookie_a = os.environ.get("H1_COOKIE_A", "")
    cookie_b = os.environ.get("H1_COOKIE_B", "")
    report_id = os.environ.get("H1_REPORT_ID", "")
    report_gid = os.environ.get("H1_REPORT_GID", "")
    if not os.path.exists(scanner_path):
        log("warn", "h1_mutation_idor.py not found — skipping")
    elif not (cookie_a and cookie_b and report_id and report_gid):
        log("warn", "H1_COOKIE_A/B, H1_REPORT_ID, H1_REPORT_GID not set — skipping h1_mutation_idor.py")
    else:
        out_file = os.path.join(idor_dir, "h1_mutation_idor_results.json")
        cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)}'
               f' --cookie-a {shlex.quote(cookie_a)}'
               f' --cookie-b {shlex.quote(cookie_b)}'
               f' --report-id {shlex.quote(report_id)}'
               f' --report-gid {shlex.quote(report_gid)}'
               f' > {shlex.quote(out_file)} 2>&1')
        ok, _ = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell redirect
        if not ok:
            log("warn", "h1_mutation_idor.py finished with non-zero exit — continuing")

    # h1_oauth_tester.py → findings/{domain}/auth_bypass/
    scanner_path = os.path.join(TOOLS_DIR, "h1_oauth_tester.py")
    if not os.path.exists(scanner_path):
        log("warn", "h1_oauth_tester.py not found — skipping")
    else:
        out_file = os.path.join(auth_dir, "h1_oauth_tester_results.json")
        cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)}'
               f' --check-cors > {shlex.quote(out_file)} 2>&1')
        ok, _ = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell redirect
        if not ok:
            log("warn", "h1_oauth_tester.py finished with non-zero exit — continuing")

    # h1_race.py → findings/{domain}/auth_bypass/
    scanner_path = os.path.join(TOOLS_DIR, "h1_race.py")
    if not os.path.exists(scanner_path):
        log("warn", "h1_race.py not found — skipping")
    elif not token_a:
        log("warn", "H1_TOKEN_A not set — skipping h1_race.py")
    else:
        out_file = os.path.join(auth_dir, "h1_race_results.json")
        cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)}'
               f' --token-a {shlex.quote(token_a)} --test 2fa'
               f' > {shlex.quote(out_file)} 2>&1')
        ok, _ = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell redirect
        if not ok:
            log("warn", "h1_race.py finished with non-zero exit — continuing")


def run_ai_llm_scan(domain: str) -> bool:
    """Run AI/LLM endpoint probing using hai_payload_builder and hai_probe (end of hunt step)."""
    log("info", f"Running AI/LLM endpoint probing for {domain}...")
    ai_dir = os.path.join(FINDINGS_DIR, domain, "ai_llm")
    os.makedirs(ai_dir, exist_ok=True)

    payload_builder = os.path.join(TOOLS_DIR, "hai_payload_builder.py")
    hai_probe = os.path.join(TOOLS_DIR, "hai_probe.py")

    if not os.path.exists(payload_builder):
        log("warn", "hai_payload_builder.py not found — skipping AI/LLM scan")
        return False

    # Step 1: Generate payloads into ai_llm dir
    payloads_dir = os.path.join(ai_dir, "payloads")
    os.makedirs(payloads_dir, exist_ok=True)
    cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(payload_builder)}'
           f' --type all --output-dir {shlex.quote(payloads_dir)}'
           f' > {shlex.quote(os.path.join(ai_dir, "payload_build.log"))} 2>&1')
    ok, _ = run_shell_cmd(cmd, timeout=120)  # nosec B602 – shell redirect
    if not ok:
        log("warn", "hai_payload_builder.py finished with non-zero exit — continuing")

    # Step 2: Probe AI endpoints using hai_probe.py (requires H1 API credentials)
    if not os.path.exists(hai_probe):
        log("warn", "hai_probe.py not found — skipping Hai API probe")
        return ok

    api_name = os.environ.get("H1_API_NAME", "")
    api_token = os.environ.get("H1_API_TOKEN", "")
    if not api_name or not api_token:
        log("warn", "H1_API_NAME/H1_API_TOKEN not set — skipping hai_probe.py")
        return ok

    out_file = os.path.join(ai_dir, "hai_probe_results.json")
    cmd = (f'{shlex.quote(sys.executable)} {shlex.quote(hai_probe)}'
           f' --api-name {shlex.quote(api_name)} --token {shlex.quote(api_token)}'
           f' --fingerprint > {shlex.quote(out_file)} 2>&1')
    probe_ok, _ = run_shell_cmd(cmd, timeout=120)  # nosec B602 – shell redirect
    if not probe_ok:
        log("warn", "hai_probe.py finished with non-zero exit — continuing")
    return ok or probe_ok


_GITHUB_HOSTS = {"github.com", "www.github.com"}
_MAX_CICD_REPOS = 5  # maximum GitHub repos to scan per target


def _is_github_url(raw: str) -> bool:
    """Return True only when the URL host is exactly github.com (or www.github.com)."""
    raw = raw.strip()
    if not raw:
        return False
    # Prepend scheme so urlparse can extract the netloc correctly.
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        host = urlparse(raw).netloc.lower()
        # Strip port if present.
        host = host.split(":")[0]
        return host in _GITHUB_HOSTS
    except Exception:
        return False


def run_cicd_scan(domain: str) -> bool:
    """Run CI/CD scanner when GitHub repository URLs are found in recon output (hunt step)."""
    urls_file = os.path.join(RECON_DIR, domain, "urls", "all.txt")
    if not os.path.isfile(urls_file):
        return False

    try:
        with open(urls_file) as f:
            lines = f.read().splitlines()
    except OSError:
        return False

    github_urls = [line.strip() for line in lines if _is_github_url(line)]
    if not github_urls:
        return False

    log("info", f"GitHub URLs found — running CI/CD scanner for {domain}...")
    script = os.path.join(TOOLS_DIR, "cicd_scanner.sh")
    if not os.path.exists(script):
        log("warn", "cicd_scanner.sh not found — skipping")
        return False

    cicd_dir = os.path.join(FINDINGS_DIR, domain, "cicd")
    os.makedirs(cicd_dir, exist_ok=True)

    ran = 0
    for raw_url in github_urls[:_MAX_CICD_REPOS]:
        # Normalize to owner/repo (strip protocol and trailing slashes/paths)
        normalized = raw_url
        for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        normalized = normalized.rstrip("/").split("?")[0].split("#")[0]
        if "/" not in normalized:
            continue  # not an owner/repo reference
        slug = normalized.replace("/", "_")
        out_file = os.path.join(cicd_dir, f"cicd_{slug}.txt")
        cmd = (f'bash {shlex.quote(script)} {shlex.quote(normalized)}'
               f' --output-dir {shlex.quote(cicd_dir)}'
               f' > {shlex.quote(out_file)} 2>&1')
        ok, _ = run_shell_cmd(cmd, timeout=300)  # nosec B602 – shell redirect
        if ok:
            ran += 1
        else:
            log("warn", f"cicd_scanner.sh had issues for {raw_url} — continuing")

    return ran > 0


def generate_reports(domain):
    """Generate reports for findings."""
    findings_dir = os.path.join(FINDINGS_DIR, domain)
    if not os.path.isdir(findings_dir):
        log("warn", f"No findings for {domain}")
        return 0

    log("info", f"Generating reports for {domain}...")
    script = os.path.join(TOOLS_DIR, "report_generator.py")
    success, output = run_cmd([sys.executable, script, findings_dir])
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

    cmd = [sys.executable, script, domain]
    if os.path.isdir(recon_dir):
        cmd.extend(["--recon-dir", recon_dir])

    try:
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
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

    # Check if we have recon data with live URLs
    recon_dir = os.path.join(RECON_DIR, domain)
    cmd = [sys.executable, script, f"https://{domain}"]
    if os.path.isdir(recon_dir):
        cmd.extend(["--recon-dir", recon_dir])
    if deep:
        cmd.append("--deep")

    try:
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
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
        ("cache_deception_scanner.py",  f'--url "{target_url}" --json --rate 1.0'),
        ("pdf_ssrf_scanner.py",         f'--url "{target_url}"'),
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
        cmd = f'{shlex.quote(sys.executable)} {shlex.quote(scanner_path)} {scanner_args} > {shlex.quote(out_file)} 2>&1'

        log("info", f"  [{scanner_name}]...")
        success, _ = run_shell_cmd(cmd, timeout=120 if quick else 300)  # nosec B602 – shell redirect
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
            'deep'  — all exotic scanners including cache deception and PDF SSRF (~20-30 min).
            'off'   — skip exotic phase entirely.

    Pipeline phases:
        1. Recon          — subdomain enum, live host discovery, JS analysis, secrets.
        2. Intel          — CVE and disclosure intel enrichment.
        3. CI/CD check    — surface CI/CD scan results from recon.
        4. Vuln scan      — nuclei + vuln_scanner.sh full pass.
        5. H1 scanners    — IDOR, mutation IDOR, OAuth, race conditions.
        6. CI/CD scan     — deep CI/CD pipeline analysis.
        7. AI/LLM probe   — payload generation + Hai API endpoint probing.
        8. Exotic scan    — configurable exotic vuln scanner suite.
        9. Web vuln scan  — SQLi (sqlmap) and JWT audit.
       10. CVE hunt       — optional CVE hunter.
       11. Zero-day fuzz  — optional zero-day fuzzer.
       12. Report gen     — markdown + JSON findings reports.
    """
    result = {"domain": domain, "success": True, "recon": False, "scan": False, "reports": 0}

    if not scan_only:
        result["recon"] = run_recon(domain, quick=quick)
        if not result["recon"]:
            log("warn", f"Recon had issues for {domain}, continuing anyway...")

        # Intel engine: run between recon and rank steps so the ranker can factor
        # in known CVEs when prioritising hosts (1C)
        recon_dir = _resolve_recon_dir(domain)
        run_intel(domain, recon_dir)

    if recon_only:
        return result

    check_cicd_results(domain)
    result["scan"] = run_vuln_scan(domain, quick=quick)

    # H1-specific scanners: IDOR, mutation IDOR, OAuth, race conditions (1A)
    run_h1_scanners(domain)

    # CI/CD scanner: only when GitHub URLs discovered in recon (1D)
    run_cicd_scan(domain)

    # AI/LLM endpoint probing: payload generation + Hai API probe (1B)
    run_ai_llm_scan(domain)

    # Exotic scanning (core 3 by default, configurable profile)
    if exotic_profile and exotic_profile != "off":
        run_exotic_scan(domain, profile=exotic_profile, quick=quick)

    # Phase 9 — standard web vuln scanners (always run, independent of exotic profile)
    run_sqlmap_targeted(domain)
    run_jwt_audit(domain)

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
