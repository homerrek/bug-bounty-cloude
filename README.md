<p align="center">
  <img src="logo.png" alt="Claude Bug Bounty Logo" width="320"/>
</p>

<div align="center">

<img src="https://img.shields.io/badge/v4.2.0-New_Scanners_%2B_Optimizations-blueviolet?style=for-the-badge" alt="v4.2.0">

# Claude Bug Bounty

### The AI-Powered Agent Harness for Professional Bug Bounty Hunting

*Your AI copilot that sees live traffic, remembers past hunts, and hunts autonomously.*
<br>
*The community made a meme coin to support the project CA: J6VzBAGnyyNEyzyHhauwg3ofRctFxnTLzQCcjUdGpump*
<sub>by <a href="https://shuvonsec.me">shuvonsec</a></sub>

<br>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-267_passing-brightgreen.svg?style=flat-square)](tests/)
[![Claude Code](https://img.shields.io/badge/Claude_Code-Plugin-D97706.svg?style=flat-square&logo=anthropic&logoColor=white)](https://claude.ai/claude-code)

<br>

<a href="#-quick-start">Quick Start</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-how-it-works">How It Works</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-commands">Commands</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-whats-new-in-v400">What's New</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="#-installation">Install</a>

<br>

```
  16 commands  ·  7 AI agents  ·  9 skill domains
  58 web2 vuln classes  ·  10 web3 bug classes
  Burp MCP  ·  HackerOne MCP  ·  Kali Integration  ·  Autonomous Mode
  60% smaller prompt footprint — same coverage, faster sessions
```

</div>

<br>

---

<br>

## The Problem

Most bug bounty toolkits give you a bag of scripts. You still have to:
- Figure out **what** to test and **in what order**
- Waste hours on **false positives** that get rejected
- Write **reports from scratch** every time
- **Forget** what worked on previous targets
- **Context-switch** between 15 different terminal windows

<br>

## The Solution

Claude Bug Bounty is an **agent harness** — not just scripts. It reasons about what to test, validates findings before you waste time writing them up, remembers what worked across targets, and generates reports that actually get paid.

<br>

<div align="center">

| Before | After |
|:---|:---|
| Run scripts manually, hope for the best | AI orchestrates 32+ tools in the right order |
| Write reports from scratch (45 min each) | Report-writer agent generates submission-ready reports in 60s |
| Forget what worked last month | Persistent memory — patterns from target A inform target B |
| Can't see live traffic from Claude | Burp MCP integration — Claude reads your proxy history |
| Hunt one endpoint at a time | `/autopilot` runs standard + exotic hunt loops with safety checkpoints |
| Miss exotic vulns (CORS, SSTI, open redirect) | 17 exotic scanners run automatically in autopilot |

</div>

<br>

---

<br>

## Quick Start

**Step 1 — Install**

```bash
git clone https://github.com/homerrek/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh
```

**Step 2 — Hunt**

```bash
claude                          # Start Claude Code

/recon target.com               # Discover attack surface
/hunt target.com                # Test for vulnerabilities
/validate                       # Check finding before writing
/report                         # Generate submission-ready report
```

**Step 3 — Go Autonomous** *(new in v3)*

```bash
/autopilot target.com --normal           # Full autonomous hunt loop (standard + exotic)
/autopilot target.com --normal --exotic deep  # + all 17 exotic scanners
/intel target.com                        # Fetch CVE + disclosure intel
/resume target.com                       # Pick up where you left off
```

**Step 4 — Hunt Exotic Vulns & Kali Tools** *(new in v4)*

```bash
/exotic target.com              # Hunt 38 exotic vuln classes with 17 scanners
/kali target.com --profile web  # Kali Linux tools integration (40+ tools)
/deep-scan target.com           # Deep network/SSL/DNS scanning
```

<br>

> **Or run tools directly** — no Claude needed:
> ```bash
> python3 tools/hunt.py --target target.com
> ./tools/recon_engine.sh target.com
> python3 tools/intel_engine.py --target target.com --tech nextjs
> ```

<br>

---

<br>

## How It Works

```
                         YOU
                          |
                    ┌─────▼─────┐
                    │   Claude   │ ◄── Burp MCP (sees your traffic)
                    │   Code     │ ◄── HackerOne MCP (program intel)
                    └─────┬─────┘
                          |
          ┌───────────────┼───────────────┐
          |               |               |
    ┌─────▼─────┐  ┌──────▼──────┐  ┌────▼────┐
    │   Recon    │  │    Hunt     │  │ Report  │
    │   Agent    │  │   Engine    │  │ Writer  │
    └─────┬─────┘  └──────┬──────┘  └────┬────┘
          |               |               |
    subfinder        scope check      H1/Bugcrowd
    httpx            vuln test        Intigriti
    katana           validate         Immunefi
    nuclei           chain A→B→C      CVSS 3.1
          |               |               |
    ┌─────▼───────────────▼───────────────▼─────┐
    │              Hunt Memory                   │
    │  journal · patterns · audit · rate limit   │
    └───────────────────────────────────────────-─┘
```

Each stage feeds the next. Claude orchestrates everything, or you run any stage independently.

<br>

---

<br>

## Commands

### Core Workflow

| Command | What It Does |
|:---|:---|
| `/recon target.com` | Full recon — subdomains, live hosts, URLs, nuclei scan |
| `/hunt target.com` | Active testing — scope check, tech detect, test highest-ROI bugs |
| `/validate` | 7-Question Gate + 4 gates — PASS / KILL / DOWNGRADE / CHAIN REQUIRED |
| `/report` | Submission-ready report for H1/Bugcrowd/Intigriti/Immunefi |
| `/chain` | Find B and C from bug A — systematic exploit chaining |
| `/scope <asset>` | Verify asset is in scope before testing |
| `/triage` | Quick 2-minute go/no-go before deep validation |
| `/web3-audit <contract>` | 10-class smart contract checklist + Foundry PoC |

### Autonomous & Memory *(new in v3)*

| Command | What It Does |
|:---|:---|
| `/autopilot target.com` | Full autonomous hunt loop — standard + exotic vuln coverage |
| `/autopilot target.com --exotic deep` | Autopilot with all 17 exotic scanners |
| `/surface target.com` | AI-ranked attack surface from recon + memory |
| `/resume target.com` | Resume previous hunt — shows what's untested |
| `/remember` | Save finding or pattern to persistent memory |
| `/intel target.com` | CVEs + disclosures cross-referenced with your hunt history |

### Exotic Vulns, Kali & Deep Scan *(new in v4)*

| Command | What It Does |
|:---|:---|
| `/exotic target.com` | Hunt 38 exotic vuln classes with 17 specialized scanners |
| `/kali target.com --profile web` | Kali Linux tools integration (40+ tools: nmap, nikto, sqlmap, ...) |
| `/deep-scan target.com` | Deep network/SSL/DNS rebinding scanning with custom Python tools |

<br>

---

<br>

## AI Agents

7 specialized agents, each tuned for its role:

| Agent | What It Does | Model |
|:---|:---|:---|
| **recon-agent** | Subdomain enum, live hosts, URL crawl, nuclei | Haiku *(fast)* |
| **report-writer** | Professional reports, impact-first, human tone | Opus *(quality)* |
| **validator** | 7-Question Gate + 4-gate finding validation | Sonnet |
| **web3-auditor** | 10-class contract audit + Foundry PoC stubs | Sonnet |
| **chain-builder** | Systematic A-B-C exploit chaining | Sonnet |
| **autopilot** | Autonomous hunt loop with circuit breaker | Sonnet |
| **recon-ranker** | Attack surface ranking from recon + memory | Haiku *(fast)* |

<br>

---

<br>

## What's New in v4.2.0

> **3 new scanners. Smarter token optimization. 56 new tests.**

<details>
<summary><b>New Scanners: CORS, SSTI, Open Redirect</b></summary>
<br>

Three new Python scanners, zero new dependencies (stdlib only):

- **`cors_scanner.py`** — 6 CORS test vectors: origin reflection, null origin (sandboxed iframe), subdomain wildcard, pre-flight bypass, credential exposure (CRITICAL), internal network origins
- **`ssti_scanner.py`** — Universal SSTI probe + 10 engine-specific payloads (Jinja2, Twig, Freemarker, ERB, Spring EL, Thymeleaf, EJS, Pug, Handlebars, Mako) + WAF bypass variants + blind time-based detection
- **`open_redirect_scanner.py`** — 18 redirect parameters, 30+ bypass techniques (protocol-relative, backslash, at-sign, encoding, fragment, parameter pollution), OAuth `redirect_uri` chain detection

</details>

<details>
<summary><b>Token Optimizer + Context Manager Enhancements</b></summary>
<br>

- **`--dedup`**: Find near-duplicate files (>80% Jaccard similarity) in a directory
- **`--compress`**: Strip comments/blanks/docstrings from files for context-efficient loading
- **`--budget N`**: Auto-select highest-priority files that fit within N tokens
- **Improved `estimate_tokens()`**: Hybrid char+word estimate for better BPE accuracy
- **`--auto-compact`**: Auto-compact context when usage hits 80%
- **`--snapshot` / `--restore` / `--diff`**: Named context snapshots for branching hunt sessions

</details>

<br>

---

<br>

## What's New in v4.1.0

> **60% smaller prompt footprint. Same full coverage.**

<details>
<summary><b>Token-Optimized Architecture</b></summary>
<br>

Every session used to load ~95,000 tokens of overlapping markdown before a single prompt was typed. v4.1.0 eliminates the duplication:

- **Root `SKILL.md`** replaced with a thin pointer — canonical content lives in `skills/bug-bounty/SKILL.md`
- **Agent files** (`autopilot`, `validator`, `chain-builder`, `report-writer`, `recon-agent`, `web3-auditor`) now carry only agent-specific behavior; duplicated methodology content replaced with `> Ref:` pointers to canonical sources
- **Command files** trimmed to usage + key details + references — the 7-Question Gate, A→B chain table, CVSS patterns, and recon pipeline each exist in exactly one place

| Scope | Before | After | Δ |
|:---|:---|:---|:---|
| Total prompt-loaded files | ~173 KB | ~69 KB | **−60%** |
| Root SKILL.md | 48.6 KB | 254 bytes | −99% |
| agents/ combined | 40.8 KB | 19.2 KB | −53% |
| commands/ (modified) | 63.0 KB | 27.9 KB | −56% |

Canonical sources kept intact and unchanged: `rules/hunting.md`, `rules/reporting.md`, `skills/bug-bounty/SKILL.md`, `commands/web3-audit.md`.

</details>

<br>

---

<br>

## What's New in v4.0.0

> **The bionic hacker gets 38 more weapons.**

<details>
<summary><b>38 Exotic Vulnerability Classes</b> — <code>/exotic</code></summary>
<br>

New skill (`skills/exotic-vulns/`) covering vuln classes 21–58: JWT attacks, prototype pollution, deserialization, XXE, WebSockets, HTTP/2 desync, DNS rebinding, CORS deep, LDAP injection, NoSQL expanded, CRLF, cache deception, postMessage XSS, CSS injection, ESI injection, PDF SSRF, dependency confusion, CORS misconfiguration, SSTI, open redirect, and more.

Profiles: `--profile quick` (6 scanners, 5–10 min), `--profile deep` (all 17, 20–30 min), `--scanner <name>` (single scanner).

</details>

<details>
<summary><b>Kali Linux Integration</b> — <code>/kali</code></summary>
<br>

`kali_integration.py` — unified orchestrator for 40+ Kali security tools with pre-configured profiles:
- `web` — nikto, sqlmap, dirb, gobuster, wpscan
- `network` — nmap, masscan
- `webapp` — Burp Suite, ZAP, sqlmap
- `password` — john, hashcat, hydra
- `enumeration` — enum4linux, smbclient
- `full` — comprehensive coverage

`kali_tool_detector.py` detects installed tools and generates install scripts for missing ones.

</details>

<details>
<summary><b>Deep Scanning</b> — <code>/deep-scan</code></summary>
<br>

Custom Python scanners for deep network analysis:
- SSL/TLS configuration (protocol versions, cipher suites, certificate validation)
- Port scanning with service detection and banner grabbing
- DNS rebinding and localhost bypass detection

Profiles: `fast` (top 20 ports), `full` (top 1000 ports), `--scanner ssl`, `--scanner dns`.

</details>

<details>
<summary><b>Context & Token Management</b></summary>
<br>

Two tools for managing long hunt sessions:
- **`token_optimizer.py`** — analyzes token usage, chunks large files, prioritizes content (CRITICAL/HIGH/MEDIUM/LOW), summarizes endpoints/IPs
- **`context_manager.py`** — session persistence, item prioritization, auto-compaction, token budget allocation (memory 15%, findings 30%, recon 25%, conversation 25%)

Combined with the v4.1.0 token-optimized architecture (60% smaller prompt footprint), sessions start with far more headroom for actual findings.

</details>

<br>

---

<br>

## What's New in v3.0.0

> **The "brain in a jar" is now a bionic hacker.**

<details>
<summary><b>Autonomous Hunt Loop</b> — <code>/autopilot</code></summary>
<br>

8-step loop that runs continuously: **scope - recon - rank - hunt - exotic - validate - report - checkpoint**

Three checkpoint modes:
- `--paranoid` — stops after every finding for your review
- `--normal` — batches findings, checkpoints every few minutes
- `--yolo` — minimal stops (still requires approval for report submissions)

Exotic scanning profiles (v4.2):
- *(default)* — CORS + SSTI + open redirect (3-5 min extra, always on)
- `--exotic quick` — + JWT, host header, dependency confusion
- `--exotic deep` — all 17 exotic scanners
- `--exotic off` — standard hunt only

Built-in safety: circuit breaker stops hammering hosts after consecutive failures, per-host rate limiting, every request logged to `audit.jsonl`, context auto-snapshotted before exotic phase.

</details>

<details>
<summary><b>Persistent Hunt Memory</b> — remember everything</summary>
<br>

- **Journal** — append-only JSONL log of every hunt action (concurrent-safe writes)
- **Pattern DB** — what technique worked on which tech stack, sorted by payout
- **Target profiles** — tested/untested endpoints, tech stack, findings
- **Cross-target learning** — patterns from target A suggested when hunting target B

</details>

<details>
<summary><b>MCP Integrations</b> — Burp + HackerOne</summary>
<br>

**Burp Suite MCP** — Claude can read your proxy history, replay requests through Burp, use Collaborator payloads. Your AI copilot now sees the same traffic you do.

**HackerOne MCP** — Public API integration:
- `search_disclosed_reports` — search Hacktivity by keyword or program
- `get_program_stats` — bounty ranges, response times, resolved counts
- `get_program_policy` — scope, safe harbor, excluded vuln classes

</details>

<details>
<summary><b>On-Demand Intel</b> — <code>/intel</code></summary>
<br>

Wraps `learn.py` + HackerOne MCP + hunt memory:
- Flags **untested CVEs** matching the target's tech stack
- Shows **new endpoints** not in your tested list
- Surfaces **cross-target patterns** from your own hunt history
- Prioritizes: CRITICAL untested > HIGH untested > already tested

</details>

<details>
<summary><b>Deterministic Scope Safety</b></summary>
<br>

`scope_checker.py` uses anchored suffix matching — code check, not LLM judgment:
- `*.target.com` matches `api.target.com` but NOT `evil-target.com`
- Excluded domains always win over wildcards
- IP addresses rejected with warning (match by domain only)
- Every test filtered through scope before execution

</details>

<br>

---

<br>

## Vulnerability Coverage

<details>
<summary><b>20 Standard Web2 Bug Classes</b> — click to expand</summary>
<br>

| Class | Key Techniques | Typical Payout |
|:---|:---|:---|
| **IDOR** | Object-level, field-level, GraphQL node(), UUID enum, method swap | $500 - $5K |
| **Auth Bypass** | Missing middleware, client-side checks, BFLA | $1K - $10K |
| **XSS** | Reflected, stored, DOM, postMessage, CSP bypass, mXSS | $500 - $5K |
| **SSRF** | Redirect chain, DNS rebinding, cloud metadata, 11 IP bypasses | $1K - $15K |
| **Business Logic** | Workflow bypass, negative quantity, price manipulation | $500 - $10K |
| **Race Conditions** | TOCTOU, coupon reuse, limit overrun, double spend | $500 - $5K |
| **SQLi** | Error-based, blind, time-based, ORM bypass, WAF bypass | $1K - $15K |
| **OAuth/OIDC** | Missing PKCE, state bypass, 11 redirect_uri bypasses | $500 - $5K |
| **File Upload** | Extension bypass, MIME confusion, polyglots, 10 bypasses | $500 - $5K |
| **GraphQL** | Introspection, node() IDOR, batching bypass, mutation auth | $1K - $10K |
| **LLM/AI** | Prompt injection, chatbot IDOR, ASI01-ASI10 framework | $500 - $10K |
| **API Misconfig** | Mass assignment, JWT attacks, prototype pollution, CORS | $500 - $5K |
| **ATO** | Password reset poisoning, token leaks, 9 takeover paths | $1K - $20K |
| **SSTI** | Jinja2, Twig, Freemarker, ERB, Thymeleaf -> RCE | $2K - $10K |
| **Subdomain Takeover** | GitHub Pages, S3, Heroku, Netlify, Azure | $200 - $5K |
| **Cloud/Infra** | S3 listing, EC2 metadata, Firebase, K8s, Docker API | $500 - $20K |
| **HTTP Smuggling** | CL.TE, TE.CL, TE.TE, H2.CL request tunneling | $5K - $30K |
| **Cache Poisoning** | Unkeyed headers, parameter cloaking, web cache deception | $1K - $10K |
| **MFA Bypass** | No rate limit, OTP reuse, response manipulation, race | $1K - $10K |
| **SAML/SSO** | XSW, comment injection, signature stripping, XXE | $2K - $20K |

</details>

<details>
<summary><b>38 Exotic Web2 Bug Classes</b> *(new in v4)* — click to expand</summary>
<br>

| Class | Key Techniques | Typical Payout |
|:---|:---|:---|
| **JWT Attacks** | alg=none, RS256→HS256 confusion, kid injection, jwk injection | $500 - $5K |
| **Prototype Pollution** | Client-side, server-side (Express/lodash/qs), PP→RCE | $1K - $10K |
| **Deserialization** | Java (ysoserial), Python pickle, PHP POP chains, .NET ViewState | $2K - $20K |
| **XXE** | Classic, blind, SSRF via XXE, SVG/XLSX/DOCX | $1K - $10K |
| **WebSocket IDOR** | Auth bypass, CSWSH, IDOR over WS, hijacking | $500 - $5K |
| **HTTP/2 Desync** | H2.CL, H2.TE, request tunneling, response queue poisoning | $5K - $30K |
| **DNS Rebinding** | Localhost bypass, Host header manipulation, internal probing | $1K - $10K |
| **CORS Deep** | Origin reflection, null origin, pre-flight bypass | $500 - $5K |
| **Insecure Randomness** | Predictable tokens, weak PRNG, time-seeded values | $500 - $5K |
| **LDAP Injection** | Auth bypass, blind injection, AND/OR logic | $1K - $10K |
| **NoSQL Injection** | MongoDB operator injection, auth bypass, blind extraction | $1K - $10K |
| **Rate Limit Bypass** | Header spoofing, endpoint rotation, IP rotation, null byte | $500 - $5K |
| **Clickjacking Advanced** | Double-frame bypass, drag-drop, touchscreen attacks | $200 - $2K |
| **CRLF Injection** | Header injection, XSS via CRLF, response splitting | $500 - $5K |
| **Web Cache Deception** | Path confusion, extension bypass, vary header abuse | $1K - $10K |
| **Server-Side PP** | Express/Mongoose/lodash server, PP→RCE escalation | $2K - $15K |
| **postMessage XSS** | Missing origin check, wildcard target, frame confusion | $500 - $5K |
| **CSS Injection** | Data exfil via attribute selectors, @import tricks | $200 - $2K |
| **Dangling Markup** | Form injection, meta refresh, attribute capture | $200 - $2K |
| **ESI Injection** | ESI includes, SSRF via ESI, XSS escalation | $1K - $10K |
| **PDF SSRF** | wkhtmltopdf, headless Chrome, html2pdf SSRF | $500 - $5K |
| **Email Header Injection** | SMTP header injection, CC/BCC injection, phishing pivot | $200 - $2K |
| **Subdomain Delegation Takeover** | Dangling NS/CNAME, zone delegation, DNS provider exploit | $500 - $5K |
| **OAuth Token Theft via Referer** | Token in Referer header, analytics leaks, postMessage | $500 - $5K |
| **Timing Side Channels** | Username enum, token comparison, crypto timing | $200 - $5K |
| **Integer Overflow** | Signed/unsigned confusion, wrap-around, price manipulation | $1K - $10K |
| **ReDoS** | Backtracking regex, catastrophic complexity, service disruption | $200 - $5K |
| **Host Header Poisoning (Advanced)** | Password reset, cache poisoning, middleware bypass | $500 - $10K |
| **GraphQL Deep** | Batching bypass, nested DoS, alias abuse, circular fragments | $1K - $10K |
| **Dependency Confusion** | Internal package hijacking, npm/PyPI/RubyGems | $500 - $30K |
| **Client-Side Desync** | Browser-assisted request smuggling, CORS bypass | $2K - $20K |
| **HTTP Parameter Pollution** | Duplicate params, WAF bypass, logic abuse | $200 - $5K |
| **Mass Assignment** | Hidden fields, JSON extra keys, admin privilege escalation | $500 - $10K |
| **Path Traversal (Advanced)** | Unicode bypass, null byte, double-encode, zip-slip | $500 - $10K |
| **WebSocket IDOR (Advanced)** | Privileged channel access, session fixation via WS | $1K - $10K |
| **CORS Misconfiguration** | Origin reflection, null origin, credential exposure, pre-flight bypass | $500 - $5K |
| **SSTI / Template Injection** | Jinja2/Twig/Freemarker/ERB/Spring EL → RCE; 10 engines detected | $2K - $20K |
| **Open Redirect** | 18 params, 30+ bypass techniques, OAuth redirect_uri chain | $200 - $3K |

</details>

<details>
<summary><b>10 Web3 Bug Classes</b> — click to expand</summary>
<br>

| Class | Frequency | Typical Payout |
|:---|:---|:---|
| **Accounting Desync** | 28% of Criticals | $50K - $2M |
| **Access Control** | 19% of Criticals | $50K - $2M |
| **Incomplete Code Path** | 17% of Criticals | $50K - $2M |
| **Off-By-One** | 22% of Highs | $10K - $100K |
| **Oracle Manipulation** | 12% of reports | $100K - $2M |
| **ERC4626 Attacks** | Moderate | $50K - $500K |
| **Reentrancy** | Classic | $10K - $500K |
| **Flash Loan** | Moderate | $100K - $2M |
| **Signature Replay** | Moderate | $10K - $200K |
| **Proxy/Upgrade** | Moderate | $50K - $2M |

</details>

<br>

---

<br>

## Tools & Architecture

<details>
<summary><b>Core Pipeline</b> — <code>tools/</code></summary>
<br>

| Tool | What It Does |
|:---|:---|
| `hunt.py` | Master orchestrator — chains recon, scan, exotic scan, report (`--exotic core/quick/deep/off`) |
| `recon_engine.sh` | Subdomain enum + DNS + live hosts + URL crawl |
| `learn.py` | CVE + disclosure intel from NVD, GitHub Advisory, HackerOne |
| `intel_engine.py` | Memory-aware intel wrapper (learn.py + HackerOne MCP + memory) |
| `validate.py` | 4-gate validation — scope, impact, dedup, CVSS |
| `report_generator.py` | H1/Bugcrowd/Intigriti report output |
| `scope_checker.py` | Deterministic scope safety with anchored suffix matching |
| `cicd_scanner.sh` | GitHub Actions SAST — wraps [sisakulint](https://github.com/sisaku-security/sisakulint) remote scan (52 rules, 81.6% GHSA coverage) |
| `mindmap.py` | Prioritized attack mindmap generator |
| `kali_integration.py` | Unified Kali tool orchestrator (40+ tools, 6 profiles) *(new in v4)* |
| `kali_tool_detector.py` | Detects installed Kali tools, generates install scripts *(new in v4)* |
| `token_optimizer.py` | Token usage analyzer, chunker, content prioritization *(new in v4)* |
| `context_manager.py` | Context window manager for long hunt sessions *(new in v4)* |

</details>

<details>
<summary><b>Vulnerability Scanners</b> — <code>tools/</code></summary>
<br>

| Tool | Target |
|:---|:---|
| `h1_idor_scanner.py` | Object-level and field-level IDOR |
| `h1_mutation_idor.py` | GraphQL mutation IDOR |
| `h1_oauth_tester.py` | OAuth misconfigs (PKCE, state, redirect_uri) |
| `h1_race.py` | Race conditions (TOCTOU, limit overrun) |
| `zero_day_fuzzer.py` | Logic bugs, edge cases, access control |
| `cve_hunter.py` | Tech fingerprinting + known CVE matching |
| `vuln_scanner.sh` | Orchestrates nuclei + dalfox + sqlmap |
| `hai_probe.py` | AI chatbot IDOR, prompt injection |
| `hai_payload_builder.py` | Prompt injection payload generator |
| `xss_scanner.py` | XSS detection (reflected, stored, DOM) |
| `sqli_scanner.py` | SQL injection (error-based, blind, WAF bypass) |
| `crlf_scanner.py` | CRLF injection + response splitting |
| `cache_deception_scanner.py` | Web cache deception attacks |
| `rate_limit_tester.py` | Rate limit bypass techniques |
| `cors_scanner.py` | CORS misconfiguration (6 test vectors, credential exposure) *(new in v4.2)* |
| `ssti_scanner.py` | SSTI detection (10 engines, WAF bypass, blind time-based) *(new in v4.2)* |
| `open_redirect_scanner.py` | Open redirect (18 params, 30+ bypass techniques, OAuth chain) *(new in v4.2)* |

</details>

<details>
<summary><b>Exotic Vulnerability Scanners</b> — <code>tools/</code> *(new in v4)*</summary>
<br>

| Tool | Target |
|:---|:---|
| `cors_scanner.py` | CORS misconfiguration (origin reflection, null origin, credential exposure) |
| `ssti_scanner.py` | SSTI (Jinja2, Twig, Freemarker, ERB, Spring EL, Thymeleaf, EJS, Pug, Handlebars, Mako) |
| `open_redirect_scanner.py` | Open redirect (18 params, 30+ bypass techniques, OAuth redirect_uri) |
| `dependency_confusion_scanner.py` | Internal package hijacking (npm, PyPI, RubyGems, Go) |
| `graphql_deep_scanner.py` | Introspection, batching, nested DoS, mutations |
| `ssl_scanner.py` | SSL/TLS config, certs, ciphers, protocol versions |
| `network_scanner.py` | Port scanning, service detection, banner grabbing |
| `dns_rebinding_tester.py` | DNS rebinding, localhost bypass, Host header tests |
| `jwt_scanner.py` | JWT attacks (alg=none, RS256→HS256, kid injection) |
| `proto_pollution_scanner.py` | Prototype pollution (client + server-side) |
| `deserial_scanner.py` | Deserialization (Java, Python, .NET, PHP, Ruby) |
| `xxe_scanner.py` | XXE (classic, blind, SSRF via XXE) |
| `websocket_scanner.py` | WebSocket IDOR, CSWSH, auth bypass |
| `host_header_scanner.py` | Host header poisoning |
| `timing_scanner.py` | Timing side channels |
| `postmessage_scanner.py` | postMessage XSS |
| `css_injection_scanner.py` | CSS injection attacks |
| `esi_scanner.py` | ESI injection |

</details>

<details>
<summary><b>MCP Integrations</b> — <code>mcp/</code></summary>
<br>

| Server | Tools Provided |
|:---|:---|
| **Burp Suite** (`burp-mcp-client/`) | Read proxy history, replay requests, Collaborator payloads |
| **HackerOne** (`hackerone-mcp/`) | `search_disclosed_reports`, `get_program_stats`, `get_program_policy` |

</details>

<details>
<summary><b>Hunt Memory System</b> — <code>memory/</code></summary>
<br>

| Module | What It Does |
|:---|:---|
| `hunt_journal.py` | Append-only JSONL hunt log (concurrent-safe via `fcntl.flock`) |
| `pattern_db.py` | Cross-target pattern DB — matches by vuln class + tech stack |
| `audit_log.py` | Every outbound request logged + per-host rate limiter + circuit breaker |
| `schemas.py` | Schema validation for all entry types (versioned) |

</details>

<details>
<summary><b>Full Directory Structure</b> — click to expand</summary>
<br>

```
claude-bug-bounty/
├── skills/                     9 skill domains (canonical SKILL.md files)
├── SKILL.md                    thin pointer → skills/bug-bounty/SKILL.md
├── commands/                   16 slash commands
├── agents/                     7 specialized AI agents
├── tools/                      50 Python/shell tools
├── memory/                     Persistent hunt memory system
├── mcp/                        MCP server integrations
│   ├── burp-mcp-client/        Burp Suite proxy
│   └── hackerone-mcp/          HackerOne public API
├── tests/                      test suite
├── rules/                      Always-active hunting + reporting rules
├── hooks/                      Session start/stop hooks
├── docs/                       Payload arsenal + technique guides
├── web3/                       Smart contract skill chain
├── scripts/                    Shell wrappers
└── wordlists/                  5 wordlists
```

</details>

<br>

---

<br>

## Installation

### Prerequisites

```bash
# macOS
brew install go python3 node jq

# Linux (Debian/Ubuntu)
sudo apt install golang python3 nodejs jq
```

### Install

```bash
git clone https://github.com/shuvonsec/claude-bug-bounty.git
cd claude-bug-bounty
chmod +x install.sh && ./install.sh     # Install skills + commands into ~/.claude/
bash install_tools.sh                    # Install recon/scan tools + sisakulint
```

### API Keys

<details>
<summary><b>Chaos API</b> (required for recon)</summary>
<br>

1. Sign up at [chaos.projectdiscovery.io](https://chaos.projectdiscovery.io)
2. Export your key:

```bash
export CHAOS_API_KEY="your-key-here"
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc
```

</details>

<details>
<summary><b>Optional API keys</b> (better subdomain coverage)</summary>
<br>

Configure in `~/.config/subfinder/config.yaml`:
- [VirusTotal](https://www.virustotal.com) — free
- [SecurityTrails](https://securitytrails.com) — free tier
- [Censys](https://censys.io) — free tier
- [Shodan](https://shodan.io) — paid

</details>

<br>

---

<br>

## The Golden Rules

These are always active. Non-negotiable.

```
 1. READ FULL SCOPE        verify every asset before the first request
 2. NO THEORETICAL BUGS    "Can attacker do this RIGHT NOW?" — if no, stop
 3. KILL WEAK FAST         Gate 0 is 30 seconds, saves hours
 4. NEVER OUT-OF-SCOPE     one request = potential ban
 5. 5-MINUTE RULE          nothing after 5 min = move on
 6. RECON ONLY AUTO        manual testing finds unique bugs
 7. IMPACT-FIRST           "worst thing if auth broken?" drives target selection
 8. SIBLING RULE           9 endpoints have auth? check the 10th
 9. A→B SIGNAL             confirming A means B exists nearby — hunt it
10. VALIDATE FIRST         7-Question Gate (15 min) before report (30 min)
```

<br>

---

<br>

## The Trilogy

| Repo | Purpose |
|:---|:---|
| **[claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)** | Full hunting pipeline — recon to report |
| **[web3-bug-bounty-hunting-ai-skills](https://github.com/shuvonsec/web3-bug-bounty-hunting-ai-skills)** | Smart contract security — 10 bug classes, Foundry PoCs |
| **[public-skills-builder](https://github.com/shuvonsec/public-skills-builder)** | Ingest 500+ writeups into Claude skill files |

<br>

---

<br>

## Contributing

PRs welcome. Best contributions:

- New vulnerability scanners or detection modules
- Payload additions to `skills/security-arsenal/SKILL.md`
- New agent definitions for specific platforms
- Real-world methodology improvements (with evidence from paid reports)
- Platform support (YesWeHack, Synack, HackenProof)

```bash
git checkout -b feature/your-contribution
git commit -m "Add: short description"
git push origin feature/your-contribution
```

<br>

---

<br>

<div align="center">

### Connect

[GitHub](https://github.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Twitter](https://x.com/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [LinkedIn](https://linkedin.com/in/shuvonsec) &nbsp;&nbsp;|&nbsp;&nbsp; [Email](mailto:shuvonsec@gmail.com)

<br>

---

**For authorized security testing only.** Only test targets within an approved bug bounty scope.<br>
Never test systems without explicit permission. Follow responsible disclosure practices.

---

<br>

MIT License

**Built by bug hunters, for bug hunters.**

If this helped you find a bug, leave a star.

</div>
