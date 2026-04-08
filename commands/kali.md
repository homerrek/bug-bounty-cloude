---
name: kali
description: Integrate Kali Linux security tools into your bug bounty workflow. Run nmap, nikto, sqlmap, gobuster, and 40+ other tools with unified configuration and finding aggregation.
---

# /kali — Kali Linux Tool Integration

Run Kali security tools with proper configuration, output parsing, and finding aggregation. Supports 40+ tools across 7 categories.

## Usage

```bash
/kali target.com --profile web         # Web app tools (nikto, sqlmap, dirb, etc.)
/kali target.com --profile network     # Network tools (nmap, masscan)
/kali target.com --tools nmap,nikto    # Specific tools only
/kali --detect                         # Detect installed tools
```

## What It Does

1. **Detects installed tools** — via `kali_tool_detector.py`
2. **Runs tools with optimal config** — pre-configured for bug bounty
3. **Parses output** — extracts findings automatically
4. **Aggregates results** — single unified report
5. **Prioritizes by severity** — CRITICAL/HIGH/MEDIUM

## Tool Profiles

### Web Application Testing
**Tools**: nmap, nikto, dirb, gobuster, sqlmap, whatweb, wpscan, zaproxy
**Use case**: Full web app security assessment
**Duration**: ~20-40 minutes

```bash
/kali target.com --profile web
```

### Network Scanning
**Tools**: nmap, masscan, netdiscover, arp-scan
**Use case**: Port scanning, service detection, network mapping
**Duration**: ~5-15 minutes

```bash
/kali 192.168.1.0/24 --profile network
```

### Web Application (Extended)
**Tools**: burpsuite, zaproxy, sqlmap, nikto, wpscan, dirb, gobuster
**Use case**: Deep web app testing with proxy integration
**Duration**: ~30-60 minutes

```bash
/kali target.com --profile webapp --burp
```

### Password Attacks
**Tools**: john, hashcat, hydra, medusa, ncrack
**Use case**: Credential testing, hash cracking
**Duration**: Variable (depends on wordlist size)

```bash
/kali target.com --profile password --wordlist rockyou.txt
```

### Enumeration
**Tools**: enum4linux, smbclient, rpcclient, ldapsearch
**Use case**: Windows/Active Directory enumeration
**Duration**: ~10-20 minutes

```bash
/kali target.com --profile enumeration
```

### Full Scan
**Tools**: nmap, nikto, dirb, sqlmap, whatweb, enum4linux
**Use case**: Comprehensive assessment (network + web)
**Duration**: ~40-60 minutes

```bash
/kali target.com --profile full
```

## Individual Tools

Run specific tools directly:

```bash
# Nmap with vuln scripts
/kali target.com --tools nmap

# Nikto web scanner
/kali target.com --tools nikto

# SQLMap for SQL injection
/kali target.com --tools sqlmap --url "https://target.com/page?id=1"

# Dirb directory bruteforce
/kali target.com --tools dirb

# Gobuster with custom wordlist
/kali target.com --tools gobuster --wordlist /path/to/wordlist.txt
```

## Tool Detection

Check which tools are installed:

```bash
/kali --detect
```

Output:
```
Kali Tool Detector

RECONNAISSANCE
  ✓ nmap (installed)
  ✓ whatweb (installed)
  ✗ masscan [HIGH] (not found)

WEBAPP
  ✓ nikto (installed)
  ✓ sqlmap (installed)
  ✓ dirb (installed)
  ✗ wpscan [MEDIUM] (not found)

Summary:
  Installed: 15/20
  Missing: 5 (3 high priority)
```

Generate install script for missing tools:

```bash
/kali --detect --install-missing
# Creates: install_missing_tools.sh
```

## Output & Findings

All output saved to `kali_output/<target>/`:

```
kali_output/target.com/
├── nmap_scan.txt           # Raw nmap output
├── nikto_scan.txt          # Raw nikto output
├── sqlmap_scan.txt         # Raw sqlmap output
├── findings.json           # Aggregated findings
└── summary.md              # Human-readable summary
```

Findings are parsed and prioritized:
- **CRITICAL**: SQL injection, RCE, deserialization
- **HIGH**: XSS, authentication bypass, sensitive data exposure
- **MEDIUM**: Version disclosure, weak SSL/TLS, open ports

## Integration with Claude Bug Bounty Workflow

```bash
# 1. Recon (discover attack surface)
/recon target.com

# 2. Basic hunting (custom Python scanners)
/hunt target.com

# 3. Kali integration (industry-standard tools)
/kali target.com --profile web

# 4. Exotic hunting (less-saturated bugs)
/exotic target.com

# 5. Validate findings
/validate

# 6. Report
/report
```

## Advanced Usage

### Custom Tool Configuration

Edit `tools/kali_integration.py` to customize tool arguments:

```python
TOOL_CONFIGS = {
    "nmap": {
        "cmd": "nmap",
        "args": ["-sV", "-sC", "-O", "--script=vuln"],
        "timeout": 300
    }
}
```

### Parallel Execution

Run multiple tools in parallel:

```bash
/kali target.com --tools nmap,nikto,dirb --parallel 3
```

### Rate Limiting

Control request rate:

```bash
/kali target.com --profile web --rate 0.5    # 0.5 requests/sec
```

### Burp Integration

Route traffic through Burp Suite:

```bash
/kali target.com --profile webapp --burp --proxy 127.0.0.1:8080
```

## Requirements

### On Kali Linux
All tools pre-installed. Just run:

```bash
./install_tools.sh --with-kali-tools
```

### On macOS/Linux
Install tools via:

```bash
# Homebrew (macOS)
brew install nmap nikto

# APT (Debian/Ubuntu)
sudo apt install nmap nikto sqlmap dirb

# Or use generated install script
/kali --detect --install-missing
chmod +x install_missing_tools.sh
./install_missing_tools.sh
```

## Limitations

- Some tools require root (nmap -O, masscan). Run with `sudo` if needed.
- Burp Suite and ZAP require manual launch.
- Metasploit requires separate `msfconsole` session.
- Some scans are noisy (IDS/IPS may detect).

## Safety Notes

- **Always verify scope** before running Kali tools.
- **Rate limiting** is enforced (default 1 req/sec).
- **Destructive tools** (sqlmap with --risk 3, metasploit exploits) require `--force` flag.
- **Logs** are saved for audit trail.

## Related Commands

- `/deep-scan` — Custom network scanners (network_scanner.py, ssl_scanner.py)
- `/exotic` — Exotic vulnerability scanners (JWT, GraphQL, dependency confusion)
- `/hunt` — Standard bug bounty hunting workflow
- `/recon` — Reconnaissance pipeline
