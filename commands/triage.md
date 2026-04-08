---
description: Quick 7-Question Gate triage on a finding before writing a report. Faster than /validate — for quick go/no-go decisions. Usage: /triage
---

# /triage

Quick triage to decide: submit or kill?

> Ref: `rules/hunting.md` (full 7-Question Gate, never-submit list, fast kill signals)

## When to Use

Before spending time writing a full report. If triage passes, run `/validate` for full 4-gate check, then `/report`.

## Usage

```
/triage
```

Describe the finding in one sentence. Example:
- "I can read other users' orders by changing user_id in /api/orders/{id}"
- "The /api/export endpoint returns 200 with data even with no auth header"

## Output

**GO:** "All 7 pass. Run /validate for full check, then /report."

**KILL [reason]:**
- "Q1 fails — no HTTP request yet"
- "Q4 fails — requires admin access"
- "Q7 fails — open redirect alone is not submittable. Chain it with OAuth theft first."

**DOWNGRADE:**
- "Q6 — you have 200 status but not actual other-user data. Reproduce with two accounts and show victim's PII in the response before reporting."
