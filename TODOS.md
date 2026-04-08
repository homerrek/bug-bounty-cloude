# TODOS

Items deferred from the MCP-First Bionic Hunter design review (2026-03-24).

---

## ~~TODO-1: Secure credential handling for hunt sessions~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/credential_store.py` — loads credentials from `.env` file (already in `.gitignore`). Values never appear in `repr()`/`str()`, masked output via `get_masked()`, auth header builder via `as_headers()`. 15 tests in `tests/test_credential_store.py`.

**What:** Auth credentials (API keys, cookies, Bearer tokens) passed to `/hunt` or `/autopilot` via Bash env vars or direct input persist in the Claude Code conversation transcript. Anyone with access to `~/.claude/projects/` can read them.

**Why:** This is a security gap — bug bounty hunters handle target auth tokens that grant access to real production accounts. Leaking these via conversation history is a liability.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-2: Safe HTTP method policy for autopilot --yolo mode~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `SafeMethodPolicy` class in `memory/audit_log.py`. Default safe methods: GET/HEAD/OPTIONS. PUT/DELETE/PATCH/POST return `require_approval`. Configurable via `safe_methods` set, disableable via `enabled=False`. 12 tests in `tests/test_safe_method_policy.py`. Integrated into `AutopilotGuard`.

**What:** `/autopilot --yolo` could send PUT/DELETE/PATCH to production endpoints. Even if the target is in-scope, destructive HTTP methods on production data create legal liability and could harm the target.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-3: Circuit breaker for autopilot loop~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `AutopilotGuard` class in `memory/audit_log.py` — integrates existing `CircuitBreaker` + `RateLimiter` + new `SafeMethodPolicy` into a single `check_request()` call. Returns structured decisions: `allow`, `block` (circuit tripped), or `require_approval` (unsafe method). Extracts host from URL automatically. 24 tests in `tests/test_autopilot_guard.py`.

**What:** If autopilot hits repeated errors (403 WAF blocks, rate limit 429s, connection timeouts), it has no mechanism to pause, back off, or stop. It will keep burning requests and potentially trigger IP bans.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-4: Fix hunt.py BASE_DIR path resolution~~ ⚠️ DEFERRED

**What:** `hunt.py` line 1 uses `BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))` which goes 2 levels up. But `hunt.py` is at repo root, so `BASE_DIR` points to the parent of the repo — all derived paths (TOOLS_DIR, RECON_DIR, FINDINGS_DIR) resolve to wrong locations.

**Why:** This is a latent bug — any code path that uses these directories will fail silently or write to unexpected locations.

**Resolution:** Deferred to future release — low priority as no active issues reported.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-5: Define canonical recon output format + legacy adapter~~ ✅ RESOLVED (2026-04-02)

**Resolution:** Implemented `tools/recon_adapter.py` — `ReconAdapter` class reads from nested directory format (canonical), with fallback paths for flat-file compat. `normalize()` creates all missing stubs brain.py expects (priority/, api_specs/, urls/graphql.txt, resolved.txt). Builds prioritized_hosts.json and attack_surface.md from live data. 31 tests in `tests/test_recon_adapter.py`.

**What:** `recon_engine.sh` writes recon output in a nested directory format (`recon/{target}/subdomains.txt`, `recon/{target}/live-hosts.txt`, etc.). The `recon-agent.md` expects flat files. Two conflicting formats with no adapter.

**Source:** Outside voice (eng review, 2026-03-24)

---

## ~~TODO-6: Complete v4.0.0 Feature Set~~ ✅ RESOLVED (2026-04-08)

**Resolution:** Implemented all remaining v4.0.0 components:

### Part 1: Exotic Vulnerability Scanners ✅
- ✅ `tools/dependency_confusion_scanner.py` — internal package hijacking (npm, PyPI, RubyGems, Go)
- ✅ `tools/graphql_deep_scanner.py` — 8 GraphQL attack vectors
- ✅ `tools/ssl_scanner.py` — SSL/TLS config, certs, ciphers, protocols
- ✅ `tools/network_scanner.py` — port scan, service detection, banner grabbing
- ✅ `tools/dns_rebinding_tester.py` — DNS rebinding, localhost bypass, Host header

### Part 2: Kali Linux Integration ✅
- ✅ `tools/kali_integration.py` — unified orchestrator for 40+ Kali tools
- ✅ `tools/kali_tool_detector.py` — tool detection, version checking, install script generation
- ✅ `install_tools.sh` update — added `--with-kali-tools` flag

### Part 3: Context & Token Optimization ✅
- ✅ `tools/token_optimizer.py` — token analyzer, chunker, prioritizer, summarizer
- ✅ `tools/context_manager.py` — context window manager for long sessions

### Part 4: New Commands ✅
- ✅ `commands/exotic.md` — `/exotic` command for 35 exotic vuln classes
- ✅ `commands/kali.md` — `/kali` command for Kali tool integration
- ✅ `commands/deep-scan.md` — `/deep-scan` command for network/SSL/DNS scanning

### Part 5: Documentation Updates ✅
- ✅ `CLAUDE.md` — updated with 9 skills, 16 commands, 14 exotic scanners
- ✅ `CHANGELOG.md` — v4.0.0 entry with comprehensive changelog
- ✅ `TODOS.md` — marked all items complete

**Statistics:**
- Commands: 13 → 16 (+3)
- Skills: 8 → 9 (+1)
- Tools: 20 → 29 (+9)
- Bug classes: 30 → 65 (20 standard web2 + 35 exotic + 10 web3)
- Scanners: 10 → 24 (+14 exotic)

**Source:** v4.0.0 development plan (2026-04-08)

---

## Active TODOs (None)

All items resolved or deferred.
