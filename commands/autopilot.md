---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
```

## What This Does

Runs the full hunt cycle without stopping for approval at each step:

```
1. SCOPE     Load and confirm program scope
2. RECON     Run recon (or use cached if < 7 days old)
3. RANK      Prioritize attack surface (recon-ranker agent)
4. HUNT      Test P1 endpoints with ALL available scanners:
               a. Tech fingerprint + CVE check (cve_hunter, mindmap)
               b. Host checks: SSL, network ports, Host header (once per host)
               c. Per-endpoint: feasibility pre-check → scanner → log
               d. Scanners: xss, sqli, idor, graphql, jwt, cache_deception,
                  crlf, pdf_ssrf, rate_limit, xxe, deserial, proto_pollution,
                  dns_rebinding, dependency_confusion, esi, host_header,
                  timing, postmessage, css_injection, race, oauth, zero_day_fuzzer,
                  kali_integration + all 14 exotic scanners
               e. Pre-check skips scanners where conditions don't exist (no JWT?
                  skip jwt_scanner — no XML input? skip xxe_scanner, etc.)
               f. If signal → go deeper (A→B chain check)
               g. If nothing after 5 min → rotate
5. VALIDATE  7-Question Gate on findings
6. REPORT    Draft reports for validated findings
7. CHECKPOINT  Present to human for review
```

## Safety Guarantees

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **PUT/DELETE/PATCH** require human approval in --yolo mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/resume target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
