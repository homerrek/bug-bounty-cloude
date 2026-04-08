---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt (standard + exotic) → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo] [--exotic quick|deep|off]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety, configurable checkpoints, and **full exotic vuln coverage** (38 classes, 17 scanners).

> Ref: `agents/autopilot.md` (full autopilot agent behavior, safety rails, scanner logic, exotic scanning profiles)

## Usage

```
/autopilot target.com                         # default: --paranoid, exotic core 3
/autopilot target.com --normal                # batch checkpoint after validation
/autopilot target.com --yolo                  # minimal checkpoints (still requires report approval)
/autopilot target.com --exotic quick          # + 6 exotic scanners (~5-10 min extra)
/autopilot target.com --exotic deep           # + all 17 exotic scanners (~20-30 min extra)
/autopilot target.com --exotic off            # standard hunt only, no exotic phase
/autopilot target.com --normal --exotic deep  # combine modes
```

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## Exotic Scanning Profiles

| Profile | Scanners | Extra Time |
|---|---|---|
| *(default)* | cors, ssti, open_redirect | ~3-5 min |
| `--exotic quick` | + jwt, host_header, dependency_confusion | ~5-10 min |
| `--exotic deep` | All 17 exotic scanners | ~20-30 min |
| `--exotic off` | Standard hunt only | 0 min |

## Hunt Phases

```
standard → exotic → validate → report → checkpoint
```

The exotic phase runs after the standard hunt on all live endpoints. Findings from both phases are validated together before checkpointing.

## Safety Guarantees

- Every URL scope-checked before any request
- Every request logged to `hunt-memory/audit.jsonl` (includes `"phase": "exotic-cors"` etc.)
- Reports NEVER auto-submitted — always requires explicit approval
- PUT/DELETE/PATCH require human approval even in --yolo mode
- Circuit breaker on 5 consecutive 403/429/timeout
- Context auto-snapshotted before exotic phase (`--snapshot pre-exotic`)

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/resume target.com` next time to continue where you left off
- Check `hunt-memory/audit.jsonl` for full request log
- Exotic findings saved to `findings/exotic/<target>/`
