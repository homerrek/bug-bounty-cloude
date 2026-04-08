---
name: deep-scan
description: Deep network and service scanning with custom Python scanners (network_scanner.py, ssl_scanner.py, dns_rebinding_tester.py). Complements /kali with deeper analysis and custom detection logic.
---

# /deep-scan — Deep Network & Service Scanner

Network-level deep scanning using custom Python scanners. Tests ports, services, SSL/TLS configuration, and DNS rebinding vulnerabilities. Complements Kali tools with deeper analysis.

## Usage

```bash
/deep-scan target.com
/deep-scan target.com --profile full
/deep-scan target.com --scanner ssl
/deep-scan 192.168.1.1 --ports 80,443,8080
```

## What It Does

1. **Network scanning** — Port discovery, service detection, banner grabbing
2. **SSL/TLS analysis** — Certificate validation, cipher suites, protocol versions
3. **DNS rebinding tests** — Localhost bypass, Host header manipulation
4. **Service-specific checks** — Redis, MongoDB, Elasticsearch unauth access
5. **Vulnerability detection** — Version disclosure, weak configs, dangerous services

## Scanners (3 custom Python tools)

| Scanner | Target | Duration | Severity Range |
|---|---|---|---|
| `network_scanner.py` | Ports, services, banners | 2-10 min | HIGH-CRITICAL |
| `ssl_scanner.py` | SSL/TLS config, certs | 1-3 min | MEDIUM-HIGH |
| `dns_rebinding_tester.py` | DNS rebinding vectors | 1-2 min | MEDIUM-CRITICAL |

## Profiles

### Quick Scan (Default)
**Ports**: Common web + database (21, 22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017)
**Duration**: ~2-3 minutes

```bash
/deep-scan target.com
```

### Fast Scan
**Ports**: Top 20 most common ports
**Duration**: ~1-2 minutes

```bash
/deep-scan target.com --profile fast
```

### Full Scan
**Ports**: Top 1000 ports
**Duration**: ~10-20 minutes

```bash
/deep-scan target.com --profile full
```

### SSL Only
**Tests**: Certificate validation, cipher suites, protocol versions, compression
**Duration**: ~1-2 minutes

```bash
/deep-scan target.com --scanner ssl
```

### DNS Rebinding Only
**Tests**: Localhost bypass, Host header manipulation, internal service probing
**Duration**: ~1 minute

```bash
/deep-scan target.com --scanner dns
```

## Scanner Details

### network_scanner.py

Port scanning with service detection and vulnerability checks.

**What it tests:**
- Open ports (TCP connect scan)
- Service banners (HTTP, FTP, SSH, etc.)
- Version disclosure in banners
- Dangerous services (FTP, Telnet, RDP, Redis, MongoDB, Elasticsearch)
- Unauthenticated access (Redis, MongoDB)

**Example findings:**
- "Redis allows unauthenticated access" (CRITICAL)
- "Elasticsearch exposed" (HIGH)
- "Unencrypted protocol: Telnet" (HIGH)
- "Version disclosure on port 80" (MEDIUM)

```bash
python3 tools/network_scanner.py --host target.com --fast
python3 tools/network_scanner.py --host target.com --ports 80,443,8080
python3 tools/network_scanner.py --host 192.168.1.1 --threads 20
```

### ssl_scanner.py

SSL/TLS configuration scanner with certificate validation.

**What it tests:**
- Certificate validity and expiration
- Certificate chain verification
- Subject Alternative Names (SAN)
- SSL/TLS protocol versions (SSLv2, SSLv3, TLS 1.0-1.3)
- Cipher suites and key strength
- SSL compression (CRIME vulnerability)

**Example findings:**
- "SSL certificate expired" (CRITICAL)
- "Weak protocol TLSv1.0 supported" (HIGH)
- "Weak cipher suite: DES-CBC3-SHA" (CRITICAL)
- "SSL compression enabled (CRIME vulnerability)" (HIGH)

```bash
python3 tools/ssl_scanner.py --host target.com
python3 tools/ssl_scanner.py --url https://target.com:8443
```

### dns_rebinding_tester.py

DNS rebinding attack detector.

**What it tests:**
- Localhost/127.0.0.1 bypass in URL parameters
- Host header accepts internal IPs
- Multiple IP resolution (DNS round-robin)
- Internal service probing via SSRF
- Cloud metadata access (AWS, GCP)

**Example findings:**
- "Cloud metadata accessible via SSRF" (CRITICAL)
- "Host header accepts internal IP: 127.0.0.1" (MEDIUM)
- "Multiple IP resolution (Round-robin DNS)" (MEDIUM)
- "Localhost/internal IP reflection detected" (HIGH)

```bash
python3 tools/dns_rebinding_tester.py --url https://target.com
python3 tools/dns_rebinding_tester.py --test-mode    # Educational mode
```

## Output & Findings

Results saved to `findings/deep-scan/<target>/`:

```
findings/deep-scan/target.com/
├── network_scan.json       # Port and service findings
├── ssl_scan.json           # SSL/TLS findings
├── dns_rebinding.json      # DNS rebinding findings
├── summary.md              # Aggregated summary
└── raw_output/             # Raw scanner outputs
    ├── network.txt
    ├── ssl.txt
    └── dns.txt
```

## Integration with Workflow

```bash
# Standard workflow
/recon target.com        # Discover attack surface
/hunt target.com         # Test web vulnerabilities
/deep-scan target.com    # Network-level deep scan
/kali target.com --profile web    # Kali tools
/exotic target.com       # Exotic vulnerabilities
/validate                # Validate findings
/report                  # Generate report
```

## Advanced Usage

### Custom Port List

```bash
/deep-scan target.com --ports 80,443,8080,8443,3000,9200
```

### Parallel Threading

```bash
/deep-scan target.com --threads 50    # Faster scanning
```

### Rate Limiting

```bash
/deep-scan target.com --rate 0.5      # Slower, more stealthy
```

### SSL Deep Analysis

```bash
/deep-scan target.com --scanner ssl --check-compression --check-heartbleed
```

### DNS Rebinding with Custom Internal IP

```bash
/deep-scan target.com --scanner dns --internal 192.168.1.1
```

## When to Use /deep-scan

- **After basic recon** — To understand exposed services
- **On network ranges** — When testing multiple IPs
- **For SSL/TLS audits** — Compliance checks (PCI-DSS, NIST)
- **When SSRF found** — Test DNS rebinding for escalation
- **Before reporting** — Validate service exposure claims

## Differences from /kali

| Feature | /deep-scan | /kali |
|---|---|---|
| Tools | Custom Python scanners | Industry-standard Kali tools |
| Focus | Network + SSL + DNS | Web + exploitation + password |
| Speed | Fast (2-10 min) | Slow (20-60 min) |
| Depth | Deep analysis per scanner | Broad coverage |
| Output | JSON + structured | Text + logs |
| Best for | Infrastructure bugs | Web application bugs |

**Use both:** `/deep-scan` for infrastructure, `/kali` for web apps.

## Safety & Compliance

- **Port scanning** may trigger IDS/IPS alerts
- **Banner grabbing** is generally safe
- **SSL testing** is non-intrusive
- **DNS rebinding tests** are safe (no exploitation)
- **Always verify scope** before scanning

## Limitations

- No UDP scanning (TCP only)
- No OS fingerprinting (use nmap for that)
- No exploitation (only detection)
- No brute force (use Hydra/Medusa for that)

## Requirements

- Python 3.8+
- No external dependencies (uses stdlib only)
- Works on macOS, Linux, Kali

Install:
```bash
# Already included in repo
chmod +x tools/network_scanner.py tools/ssl_scanner.py tools/dns_rebinding_tester.py
```

## Examples

### Quick network scan
```bash
/deep-scan api.target.com
```

### Full network scan with SSL analysis
```bash
/deep-scan target.com --profile full --scanner ssl
```

### Test multiple hosts
```bash
/deep-scan target1.com,target2.com,target3.com
```

### Scan internal network range (if in scope!)
```bash
/deep-scan 192.168.1.0/24 --fast
```

## Related Commands

- `/kali` — Kali Linux tool integration (nmap, nikto, sqlmap)
- `/exotic` — Exotic vulnerability scanning (JWT, GraphQL, dependency confusion)
- `/recon` — Subdomain enumeration and URL discovery
- `/hunt` — Web application vulnerability testing
