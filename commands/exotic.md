---
name: exotic
description: Hunt exotic and less-known vulnerability classes (JWT, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, and 28 more). Leverages the exotic-vulns skill with 35 bug classes (21-55) and 14 specialized scanners.
---

# /exotic — Exotic Vulnerability Hunter

Targets 35 less-saturated, high-signal bug classes that most hunters miss. Uses specialized scanners for deep testing of JWT attacks, GraphQL abuse, dependency confusion, SSL/TLS misconfigurations, and more.

## Usage

```bash
/exotic target.com
/exotic target.com --profile deep     # All 14 scanners
/exotic target.com --profile quick    # Top 6 scanners only
/exotic target.com --scanner jwt      # Single scanner
```

## What It Does

1. **Loads exotic-vulns skill** — 35 bug classes with root cause analysis, payloads, bypass tables
2. **Runs specialized scanners** — 14 Python tools for deep testing
3. **Prioritizes findings** — High-signal bugs first
4. **Integrates with validation** — Runs /validate on any findings

## Scanners (14 total)

| Scanner | Target Bug Class | Priority |
|---|---|---|
| `jwt_scanner.py` | JWT attacks (alg=none, RS256→HS256, kid injection, jku spoofing) | HIGH |
| `proto_pollution_scanner.py` | Prototype pollution (client-side + server-side) | HIGH |
| `graphql_deep_scanner.py` | GraphQL (introspection, batching, nested DoS, alias bypass, circular fragments) | HIGH |
| `deserial_scanner.py` | Deserialization (Java, Python pickle, .NET, PHP, Ruby) | CRITICAL |
| `xxe_scanner.py` | XXE (classic, blind, SSRF via XXE, XInclude, SVG XXE) | HIGH |
| `websocket_scanner.py` | WebSocket (IDOR, CSWSH, auth bypass, injection) | MEDIUM |
| `host_header_scanner.py` | Host header poisoning (password reset, cache poisoning, routing SSRF) | HIGH |
| `timing_scanner.py` | Timing side channels (password length, HMAC, username enum) | MEDIUM |
| `postmessage_scanner.py` | postMessage XSS, wildcard origin, data exfiltration | MEDIUM |
| `css_injection_scanner.py` | CSS injection (attribute selectors, keylogger, data exfil) | MEDIUM |
| `esi_scanner.py` | ESI injection (Edge Side Includes) | LOW |
| `dependency_confusion_scanner.py` | Dependency confusion (internal package hijacking) | CRITICAL |
| `ssl_scanner.py` | SSL/TLS misconfig (weak ciphers, expired certs, protocol downgrade) | MEDIUM |
| `dns_rebinding_tester.py` | DNS rebinding (localhost bypass, internal service probing) | HIGH |

## Profiles

**`--profile quick`** (6 scanners, ~5-10 min)
- JWT, GraphQL, dependency confusion, host header, deserialization, XXE

**`--profile deep`** (all 14 scanners, ~20-30 min)
- All scanners + extended payloads + timeout extended

**`--scanner <name>`** (single scanner)
- Run only one specific scanner

## Examples

### Quick scan (top 6)
```bash
/exotic api.target.com --profile quick
```

### Full deep scan
```bash
/exotic target.com --profile deep --rate 0.5
```

### Single scanner (JWT attacks only)
```bash
/exotic https://target.com/api --scanner jwt
```

### With custom auth header
```bash
/exotic target.com --header "Authorization: Bearer TOKEN" --scanner graphql
```

## Output

Findings are saved to `findings/exotic/<target>/` with:
- Scanner-specific reports
- Aggregated findings JSON
- CVSS scores per finding
- Validation suggestions

## Integration with Workflow

This command is designed to be used after basic recon:

```bash
# 1. Recon
/recon target.com

# 2. Basic hunting
/hunt target.com

# 3. Exotic hunting (less-saturated bugs)
/exotic target.com --profile quick

# 4. Validate any findings
/validate

# 5. Report
/report
```

## When to Use /exotic

- After exhausting common bug classes (IDOR, XSS, SSRF basics)
- On mature, well-tested targets (already triaged common bugs)
- When looking for high-severity, less-saturated findings
- For targets with strong WAF (exotic techniques bypass better)
- During low-hanging fruit depletion phase

## Notes

- **Rate limiting**: Default 1 req/sec. Increase with `--rate 2.0` for faster scanning.
- **Authentication**: Many scanners support `--header` for auth tokens.
- **Dry run**: Use `--dry-run` to see what would be tested without sending requests.
- **Token optimization**: Large scan outputs are auto-chunked via `token_optimizer.py`.

## Related Commands

- `/hunt` — Standard vulnerability hunting (web2 classes 1-20)
- `/validate` — 7-Question Gate on findings
- `/deep-scan` — Network-level scanning (nmap, masscan, service detection)
- `/kali` — Kali Linux tool integration
