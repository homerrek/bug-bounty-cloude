# Claude Bug Bounty — Plugin Guide

Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

## Skills

| Skill | Domain |
|---|---|
| `skills/bug-bounty/` | Master workflow — recon to report, all vuln classes, LLM testing, chains |
| `skills/bb-methodology/` | Hunting mindset + 5-phase workflow + tool routing + session discipline |
| `skills/web2-recon/` | Subdomain enum, live host discovery, URL crawling, nuclei |
| `skills/web2-vuln-classes/` | 20 bug classes with bypass tables |
| `skills/exotic-vulns/` | 38 exotic vuln classes (21-58) — JWT, prototype pollution, XXE, WebSocket, HTTP/2 desync, DNS rebinding, CORS deep, SSTI, open redirect |
| `skills/security-arsenal/` | Payloads, bypass tables, gf patterns, always-rejected list |
| `skills/web3-audit/` | 10 smart contract bug classes, Foundry PoC template |
| `skills/report-writing/` | H1/Bugcrowd/Intigriti/Immunefi report templates, CVSS 3.1 |
| `skills/triage-validation/` | 7-Question Gate, 4 gates, never-submit list |

## Commands

| Command | Usage |
|---|---|
| `/recon target.com` | Full recon pipeline |
| `/hunt target.com` | Start hunting |
| `/validate` | Run 7-Question Gate on current finding |
| `/report` | Write submission-ready report |
| `/chain` | Build A→B→C exploit chain |
| `/scope <asset>` | Verify asset is in scope |
| `/triage` | Quick 7-Question Gate |
| `/web3-audit <contract.sol>` | Smart contract audit |
| `/autopilot target.com --normal` | Autonomous hunt loop |
| `/surface target.com` | Ranked attack surface |
| `/resume target.com` | Pick up previous hunt |
| `/remember` | Log finding to hunt memory |
| `/intel target.com` | Fetch CVE + disclosure intel |
| `/exotic target.com` | Hunt 38 exotic vuln classes |
| `/kali target.com --profile web` | Kali Linux tools integration |
| `/deep-scan target.com` | Deep network/SSL/DNS scanning |

## Agents

`recon-agent`, `report-writer`, `validator`, `web3-auditor`, `chain-builder`, `autopilot`, `recon-ranker`

## Rules (always active)

- `rules/hunting.md` — 20 critical hunting rules
- `rules/reporting.md` — report quality rules

## Tools

**Core:** `hunt.py`, `recon_engine.sh`, `validate.py`, `report_generator.py`, `learn.py`, `intel_engine.py`, `scope_checker.py`, `cicd_scanner.sh`, `recon_adapter.py`, `target_selector.py`, `credential_store.py`, `vuln_scanner.sh`, `h1_run.sh`

**Web Scanners:** `xss_scanner.py`, `sqli_scanner.py`, `cache_deception_scanner.py`, `crlf_scanner.py`, `pdf_ssrf_scanner.py`, `rate_limit_tester.py`, `zero_day_fuzzer.py`, `cors_scanner.py`, `ssti_scanner.py`, `open_redirect_scanner.py`

**Exotic Scanners:** `dependency_confusion_scanner.py`, `graphql_deep_scanner.py`, `ssl_scanner.py`, `network_scanner.py`, `dns_rebinding_tester.py`, `jwt_scanner.py`, `proto_pollution_scanner.py`, `deserial_scanner.py`, `xxe_scanner.py`, `websocket_scanner.py`, `host_header_scanner.py`, `timing_scanner.py`, `postmessage_scanner.py`, `css_injection_scanner.py`, `esi_scanner.py`

**H1-Specific:** `h1_idor_scanner.py`, `h1_mutation_idor.py`, `h1_oauth_tester.py`, `h1_race.py`

**Intel & Payloads:** `cve_hunter.py`, `hai_payload_builder.py`, `hai_probe.py`, `hai_browser_recon.js`, `sneaky_bits.py`, `mindmap.py`

**Kali:** `kali_integration.py`, `kali_tool_detector.py`

**Context:** `token_optimizer.py`, `context_manager.py`

**MCP:** `mcp/burp-mcp-client/`, `mcp/hackerone-mcp/`

**Memory:** `memory/hunt_journal.py`, `memory/pattern_db.py`, `memory/audit_log.py`, `memory/schemas.py`

## Quick Start

```bash
claude
# /recon target.com → /hunt target.com → /validate → /report
# /exotic target.com | /kali target.com --profile web | /deep-scan target.com
```

```bash
chmod +x install.sh && ./install.sh
```

## Critical Rules

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — proof of exploit required
3. Run 7-Question Gate BEFORE writing any report
4. N/A submissions hurt your validity ratio — triage first
5. 5-minute rule — nothing after 5 min = move on
