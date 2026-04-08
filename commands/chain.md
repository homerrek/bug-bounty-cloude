---
description: Build an exploit chain — given bug A, finds B and C to combine for higher severity and payout. Usage: /chain
---

# /chain

Build an A→B→C exploit chain for higher severity and payout.

> Ref: `agents/chain-builder.md` (chain-building process), `skills/bug-bounty/SKILL.md` (A→B chain table + known high-value chains)

## When to Use

After confirming a standalone finding that:
- Is on the "conditionally valid" list (open redirect, SSRF DNS-only, etc.)
- Has been validated but classified as Low
- Could be Medium or High if combined with another finding

## Usage

```
/chain
```

Describe bug A when prompted: bug class, endpoint, what you can do with it, target platform.

## Time-Box Rules

```
If B NOT confirmed in 20 minutes → submit A, move on
If A + B + C confirmed → STOP. Submit all three. Don't look for D.
If B requires precondition you can't test → note in A's report, move on
If 3 consecutive B candidates fail Gate 0 → cluster is dry, stop
```

## Rabbit Hole Signals (stop immediately)

- You've been on B for 30+ min with no PoC
- You're on your 4th "maybe" candidate
- B needs 3+ simultaneous preconditions
- You keep saying "this could lead to..." without an HTTP request
