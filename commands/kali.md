---
name: kali
description: Integrate Kali Linux security tools into your bug bounty workflow. Run nmap, nikto, sqlmap, gobuster, and 40+ other tools with unified configuration and finding aggregation.
---

# /kali — Kali Linux Tool Integration

Run Kali security tools with optimal configuration, output parsing, and finding aggregation.

## Usage

```bash
/kali target.com --profile web         # Web app tools
/kali target.com --profile network     # Network tools
/kali target.com --tools nmap,nikto    # Specific tools only
/kali --detect                         # Detect installed tools
```

## Profiles

| Profile | Tools | Duration |
|---|---|---|
| `web` | nmap, nikto, dirb, gobuster, sqlmap, whatweb, wpscan, zaproxy | 20-40 min |
| `network` | nmap, masscan, netdiscover, arp-scan | 5-15 min |
| `webapp` | burpsuite, zaproxy, sqlmap, nikto, wpscan, dirb, gobuster | 30-60 min |
| `password` | john, hashcat, hydra, medusa, ncrack | variable |
| `enumeration` | enum4linux, smbclient, rpcclient, ldapsearch | 10-20 min |
| `full` | nmap, nikto, dirb, sqlmap, whatweb, enum4linux | 40-60 min |

## Individual Tools

```bash
/kali target.com --tools nmap
/kali target.com --tools nikto
/kali target.com --tools sqlmap --url "https://target.com/page?id=1"
/kali target.com --tools gobuster --wordlist /path/to/wordlist.txt
```

## Tool Detection

```bash
/kali --detect                    # Check which tools are installed
/kali --detect --install-missing  # Generate install script
```

## Output

Results in `kali_output/<target>/`: `nmap_scan.txt`, `nikto_scan.txt`, `sqlmap_scan.txt`, `findings.json`, `summary.md`

## Advanced Options

```bash
/kali target.com --tools nmap,nikto,dirb --parallel 3    # parallel execution
/kali target.com --profile web --rate 0.5                # rate limiting
/kali target.com --profile webapp --burp --proxy 127.0.0.1:8080  # Burp proxy
```

## Installation

```bash
# Kali Linux: already installed — ./install_tools.sh --with-kali-tools
# macOS: brew install nmap nikto
# Debian/Ubuntu: sudo apt install nmap nikto sqlmap dirb
# Or: /kali --detect --install-missing && ./install_missing_tools.sh
```

## Safety Notes

- Always verify scope before running
- Rate limiting enforced (default 1 req/sec)
- Destructive tools (sqlmap --risk 3, metasploit exploits) require --force flag
- Some tools require root (nmap -O, masscan)
- All runs logged for audit trail
