---
name: exotic
description: Hunt exotic and less-known vulnerability classes (JWT, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, and 28 more). Leverages the exotic-vulns skill with 35 bug classes (21-55) and 14 specialized scanners.
---

# /exotic — Exotic Vulnerability Hunter

Targets 35 less-saturated, high-signal bug classes that most hunters miss.

## Usage

```bash
/exotic target.com
/exotic target.com --profile deep     # All 14 scanners
/exotic target.com --profile quick    # Top 6 scanners only
/exotic target.com --scanner jwt      # Single scanner
/exotic target.com --header "Authorization: Bearer TOKEN" --scanner graphql
```

## Scanners (14 total)

| Scanner | Bug Class | Priority |
|---|---|---|
| `jwt_scanner.py` | JWT attacks (alg=none, RS256→HS256, kid injection) | HIGH |
| `proto_pollution_scanner.py` | Prototype pollution (client + server-side) | HIGH |
| `graphql_deep_scanner.py` | GraphQL (introspection, batching, nested DoS, alias bypass) | HIGH |
| `deserial_scanner.py` | Deserialization (Java, Python pickle, .NET, PHP, Ruby) | CRITICAL |
| `xxe_scanner.py` | XXE (classic, blind, SSRF via XXE, SVG XXE) | HIGH |
| `websocket_scanner.py` | WebSocket (IDOR, CSWSH, auth bypass, injection) | MEDIUM |
| `host_header_scanner.py` | Host header poisoning | HIGH |
| `timing_scanner.py` | Timing side channels | MEDIUM |
| `postmessage_scanner.py` | postMessage XSS, wildcard origin | MEDIUM |
| `css_injection_scanner.py` | CSS injection (attribute selectors, keylogger) | MEDIUM |
| `esi_scanner.py` | ESI injection | LOW |
| `dependency_confusion_scanner.py` | Dependency confusion (internal package hijacking) | CRITICAL |
| `ssl_scanner.py` | SSL/TLS misconfig | MEDIUM |
| `dns_rebinding_tester.py` | DNS rebinding, localhost bypass | HIGH |

## Profiles

- `--profile quick` — JWT, GraphQL, dependency confusion, host header, deserialization, XXE (~5-10 min)
- `--profile deep` — All 14 scanners + extended payloads (~20-30 min)
- `--scanner <name>` — Single scanner only

## Output

Findings in `findings/exotic/<target>/`: scanner reports, aggregated JSON, CVSS scores, validation suggestions.

## Notes

- Rate limiting: default 1 req/sec. Increase with `--rate 2.0`.
- Use `--dry-run` to preview what would be tested without sending requests.
- Large scan outputs are auto-chunked via `token_optimizer.py`.
- Use after exhausting common bug classes or on mature, well-tested targets.
