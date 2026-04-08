---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

> Ref: `agents/autopilot.md` (full autopilot agent behavior, safety rails, scanner logic)

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
```

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## Safety Guarantees

- Every URL scope-checked before any request
- Every request logged to `hunt-memory/audit.jsonl`
- Reports NEVER auto-submitted — always requires explicit approval
- PUT/DELETE/PATCH require human approval even in --yolo mode
- Circuit breaker on 5 consecutive 403/429/timeout

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/resume target.com` next time to continue where you left off
- Check `hunt-memory/audit.jsonl` for full request log
