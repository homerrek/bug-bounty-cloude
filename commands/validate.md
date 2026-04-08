---
description: Validate a finding — runs 7-Question Gate + 4-gate checklist. Kills weak findings before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

> Ref: `agents/validator.md` (full validation logic), `rules/hunting.md` (7-Question Gate, 4 gates, never-submit list)

## Usage

```
/validate
```

Describe the finding when prompted: endpoint, bug class, what the PoC shows, target program.

## What This Does

1. Runs 7-Question Gate (one wrong answer = kill it)
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Outputs: PASS → proceed to /report, or KILL → move on

## Output

**PASS:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**KILL:** "Q[N] fails because [reason]. Kill this finding. Move on."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."
