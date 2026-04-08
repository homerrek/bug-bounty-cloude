# Claude Bug Bounty — Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## What's Here

### Skills (9 domains — load with `/bug-bounty`, `/web2-recon`, etc.)

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | **Hunting mindset + 5-phase non-linear workflow + tool routing + session discipline** |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 18 bug classes with bypass tables (SSRF, open redirect, file upload, Agentic AI) |
| `skills/exotic-vulns/` | **35 exotic vuln classes (21-55) — JWT, prototype pollution, XXE, WebSocket, HTTP/2 desync, DNS rebinding, and 29 more** |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template, pre-dive kill signals |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1, human tone |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list, conditionally valid table |

### Commands (16 slash commands)

| Command | Usage |
|---|---|
| `/recon` | `/recon target.com` — full recon pipeline |
| `/hunt` | `/hunt target.com` — start hunting |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope |
| `/triage` | `/triage` — quick 7-Question Gate |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/autopilot` | `/autopilot target.com --normal` — autonomous hunt loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/resume` | `/resume target.com` — pick up previous hunt |
| `/remember` | `/remember` — log finding to hunt memory |
| `/intel` | `/intel target.com` — fetch CVE + disclosure intel |
| `/exotic` | `/exotic target.com` — hunt 35 exotic vuln classes with 14 specialized scanners |
| `/kali` | `/kali target.com --profile web` — integrate Kali Linux tools (nmap, nikto, sqlmap, 40+ more) |
| `/deep-scan` | `/deep-scan target.com` — deep network/SSL/DNS scanning with custom Python tools |

### Agents (7 specialized agents)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — generates H1/Bugcrowd/Immunefi reports
- `validator` — 4-gate checklist on a finding
- `web3-auditor` — smart contract bug class analysis
- `chain-builder` — builds A→B→C exploit chains
- `autopilot` — autonomous hunt loop (scope→recon→rank→hunt→validate→report)
- `recon-ranker` — attack surface ranking from recon output + memory

### Rules (always active)

- `rules/hunting.md` — 17 critical hunting rules
- `rules/reporting.md` — report quality rules

### Tools (Python/shell — in `tools/`)

**Core Pipeline:**
- `tools/hunt.py` — master orchestrator
- `tools/recon_engine.sh` — subdomain + URL discovery
- `tools/validate.py` — 4-gate finding validator
- `tools/report_generator.py` — report writer
- `tools/learn.py` — CVE + disclosure intel
- `tools/intel_engine.py` — on-demand intel with memory context
- `tools/scope_checker.py` — deterministic scope safety checker
- `tools/cicd_scanner.sh` — GitHub Actions workflow scanner (sisakulint wrapper, remote scan)
- `tools/recon_adapter.py` — recon output normalizer (unified API for agents consuming recon data)
- `tools/target_selector.py` — HackerOne target selector + ranker (public programs, scoring)
- `tools/credential_store.py` — secure credential loader from .env (never persisted to hunt memory)
- `tools/vuln_scanner.sh` — automated vuln checks against recon results
- `tools/h1_run.sh` — HackerOne hunt master runner (orchestrates all H1 automation tools)

**Web Vulnerability Scanners:**
- `tools/xss_scanner.py` — advanced XSS scanner (50+ payloads, reflected/stored/DOM, CSP bypass)
- `tools/sqli_scanner.py` — advanced SQLi scanner (error/blind/time-based/union injection)
- `tools/cache_deception_scanner.py` — Web Cache Deception scanner (path confusion, cache poisoning)
- `tools/crlf_scanner.py` — CRLF injection / HTTP response splitting scanner
- `tools/pdf_ssrf_scanner.py` — HTML-to-PDF generator detection + SSRF/local file read testing
- `tools/rate_limit_tester.py` — rate limit bypass scanner (IP rotation headers, padding, method swap)
- `tools/zero_day_fuzzer.py` — business logic / zero-day fuzzer (race conditions, logic flaws, edge cases)

**Exotic Vulnerability Scanners (14 tools):**
- `tools/dependency_confusion_scanner.py` — internal package hijacking detector
- `tools/graphql_deep_scanner.py` — GraphQL introspection, batching, nested DoS, mutations
- `tools/ssl_scanner.py` — SSL/TLS config, certs, ciphers, protocol versions
- `tools/network_scanner.py` — port scanning, service detection, banner grabbing
- `tools/dns_rebinding_tester.py` — DNS rebinding, localhost bypass, Host header tests
- `tools/jwt_scanner.py` — JWT attacks (alg=none, RS256→HS256, kid injection)
- `tools/proto_pollution_scanner.py` — prototype pollution (client + server-side)
- `tools/deserial_scanner.py` — deserialization (Java, Python, .NET, PHP, Ruby)
- `tools/xxe_scanner.py` — XXE (classic, blind, SSRF via XXE)
- `tools/websocket_scanner.py` — WebSocket IDOR, CSWSH, auth bypass
- `tools/host_header_scanner.py` — Host header poisoning
- `tools/timing_scanner.py` — timing side channels
- `tools/postmessage_scanner.py` — postMessage XSS
- `tools/css_injection_scanner.py` — CSS injection attacks
- `tools/esi_scanner.py` — ESI injection

**HackerOne-Specific Tools:**
- `tools/h1_idor_scanner.py` — cross-user IDOR scanner (GraphQL queries/mutations, Account A vs B)
- `tools/h1_mutation_idor.py` — mutation IDOR battery (privileged mutations across accounts)
- `tools/h1_oauth_tester.py` — OAuth/auth flow tester (state CSRF, redirect_uri bypass, 2FA bypass)
- `tools/h1_race.py` — race condition tester (bounty double-spend, 2FA rate limits, negative bounty)

**Intelligence & Payload Tools:**
- `tools/cve_hunter.py` — tech fingerprinting + CVE lookup against detected stack
- `tools/hai_payload_builder.py` — VAPT payload library + LLM/invisible prompt injection generator
- `tools/hai_probe.py` — HackerOne AI Copilot fingerprinter
- `tools/hai_browser_recon.js` — browser-based recon (headers, JS sources, WebSocket detection)
- `tools/sneaky_bits.py` — invisible prompt injection encoder (U+2062/U+2064 steganography)
- `tools/mindmap.py` — attack mindmap + prioritized hunting checklist generator (Mermaid output)

**Kali Integration:**
- `tools/kali_integration.py` — unified Kali tool orchestrator (40+ tools)
- `tools/kali_tool_detector.py` — detect installed Kali tools, generate install scripts

**Context & Token Management:**
- `tools/token_optimizer.py` — token usage analyzer, chunker, summarizer
- `tools/context_manager.py` — context window manager for long hunt sessions

### MCP Integrations (in `mcp/`)

- `mcp/burp-mcp-client/` — Burp Suite proxy integration
- `mcp/hackerone-mcp/` — HackerOne public API (Hacktivity, program stats, policy)

### Hunt Memory (in `memory/`)

- `memory/hunt_journal.py` — append-only hunt log (JSONL)
- `memory/pattern_db.py` — cross-target pattern learning
- `memory/audit_log.py` — request audit log, rate limiter, circuit breaker
- `memory/schemas.py` — schema validation for all data

## Start Here

```bash
claude
# /recon target.com
# /hunt target.com
# /validate   (after finding something)
# /report     (after validation passes)

# Advanced hunting (v4.0.0+)
# /exotic target.com      (hunt 35 exotic vuln classes)
# /kali target.com --profile web    (Kali tools integration)
# /deep-scan target.com   (network/SSL/DNS deep scanning)
```

## Install Skills

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast — N/A hurts your validity ratio
5. 5-minute rule — nothing after 5 min = move on
