---
name: deep-scan
description: Deep network and service scanning with custom Python scanners (network_scanner.py, ssl_scanner.py, dns_rebinding_tester.py). Complements /kali with deeper analysis and custom detection logic.
---

# /deep-scan — Deep Network & Service Scanner

Network-level deep scanning using custom Python scanners. Tests ports, services, SSL/TLS configuration, and DNS rebinding vulnerabilities.

## Usage

```bash
/deep-scan target.com
/deep-scan target.com --profile full
/deep-scan target.com --scanner ssl
/deep-scan 192.168.1.1 --ports 80,443,8080
```

## Scanners

| Scanner | Target | Duration | Severity |
|---|---|---|---|
| `network_scanner.py` | Ports, services, banners | 2-10 min | HIGH-CRITICAL |
| `ssl_scanner.py` | SSL/TLS config, certs | 1-3 min | MEDIUM-HIGH |
| `dns_rebinding_tester.py` | DNS rebinding vectors | 1-2 min | MEDIUM-CRITICAL |

## Profiles

| Profile | Ports | Duration |
|---|---|---|
| Default (quick) | Common web + database ports | ~2-3 min |
| `--profile fast` | Top 20 ports | ~1-2 min |
| `--profile full` | Top 1000 ports | ~10-20 min |
| `--scanner ssl` | SSL only | ~1-2 min |
| `--scanner dns` | DNS rebinding only | ~1 min |

## Scanner Details

**network_scanner.py** — port scanning, service banners, version disclosure, dangerous services (FTP, Telnet, RDP, Redis, MongoDB, Elasticsearch), unauthenticated access checks.

**ssl_scanner.py** — cert validity/expiration/chain, SAN, SSL/TLS protocol versions, cipher suites, SSL compression (CRIME).

**dns_rebinding_tester.py** — localhost/127.0.0.1 bypass, Host header accepts internal IPs, cloud metadata access (AWS, GCP).

## Direct Tool Commands

```bash
python3 tools/network_scanner.py --host target.com --fast
python3 tools/ssl_scanner.py --host target.com
python3 tools/dns_rebinding_tester.py --url https://target.com
```

## Output

Results saved to `findings/deep-scan/<target>/`:
- `network_scan.json`, `ssl_scan.json`, `dns_rebinding.json`, `summary.md`

## Advanced Options

```bash
/deep-scan target.com --ports 80,443,8080,8443,3000,9200   # custom ports
/deep-scan target.com --threads 50                          # faster
/deep-scan target.com --rate 0.5                            # stealthier
/deep-scan target.com --scanner ssl --check-compression --check-heartbleed
```

## vs /kali

| Feature | /deep-scan | /kali |
|---|---|---|
| Tools | Custom Python | Industry-standard Kali |
| Focus | Network + SSL + DNS | Web + exploitation |
| Speed | Fast (2-10 min) | Slow (20-60 min) |
| Best for | Infrastructure bugs | Web app bugs |

## Safety Notes

- Port scanning may trigger IDS/IPS alerts
- SSL testing and banner grabbing are non-intrusive
- DNS rebinding tests are safe (no exploitation)
- Always verify scope before scanning
- No UDP, no OS fingerprinting, no exploitation, no brute force

## Requirements

Python 3.8+, no external dependencies (stdlib only). Works on macOS, Linux, Kali.
