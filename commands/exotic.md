---
name: exotic
description: Hunt exotic and less-known vulnerability classes (JWT, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, CORS deep, SSTI, open redirect, and 28 more). Leverages the exotic-vulns skill with 38 bug classes and 17 specialized scanners.
---

# /exotic — Exotic Vulnerability Hunter

Targets 38 less-saturated, high-signal bug classes that most hunters miss.

## Usage

```bash
/exotic target.com
/exotic target.com --profile deep     # All 17 scanners
/exotic target.com --profile quick    # Top 6 scanners only
/exotic target.com --scanner jwt      # Single scanner
/exotic target.com --header "Authorization: Bearer TOKEN" --scanner graphql
```

## Scanners (17 total)

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
| `cors_scanner.py` | CORS misconfiguration (origin reflection, null origin, credentials) | HIGH |
| `ssti_scanner.py` | Server-Side Template Injection (Jinja2, Twig, Freemarker, ERB, etc.) | CRITICAL |
| `open_redirect_scanner.py` | Open redirect (18 params, 30+ bypass techniques, OAuth redirect_uri) | HIGH |

## Profiles

- `--profile quick` — JWT, GraphQL, dependency confusion, host header, deserialization, XXE (~5-10 min)
- `--profile deep` — All 17 scanners + extended payloads (~20-30 min)
- `--scanner <name>` — Single scanner only

## Output

Findings in `findings/exotic/<target>/`: scanner reports, aggregated JSON, CVSS scores, validation suggestions.

## Notes

- Rate limiting: default 1 req/sec. Increase with `--rate 2.0`.
- Use `--dry-run` to preview what would be tested without sending requests.
- Large scan outputs are auto-chunked via `token_optimizer.py`.
- Use after exhausting common bug classes or on mature, well-tested targets.
