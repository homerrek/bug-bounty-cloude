---
description: Write a submission-ready bug bounty report. Generates H1/Bugcrowd/Intigriti/Immunefi format with CVSS 3.1 score, proof of concept, impact statement, and remediation. Run /validate first. Usage: /report
---

# /report

Generate a submission-ready bug bounty report.

> Ref: `agents/report-writer.md` (full report templates + CVSS guide), `rules/reporting.md` (writing rules, escalation language, title formula)

## Pre-Conditions

Run `/validate` first. All 4 gates must pass before running this command.
Never write a report before validating — N/A submissions hurt your validity ratio.

## Usage

```
/report
```

Provide: Platform, bug class, endpoint, test accounts + IDs, exact HTTP request, exact response showing impact, tech stack.

## What This Generates

1. Title: `[Bug Class] in [Endpoint] allows [actor] to [impact]`
2. Summary paragraph (impact-first, no "could potentially")
3. CVSS 3.1 score and vector string
4. Steps to Reproduce with copy-paste HTTP requests
5. Impact statement with quantification
6. Recommended fix (1-2 sentences, specific)

## Final Checklist Before Submitting

```
[ ] Title follows formula
[ ] First sentence states exact impact
[ ] HTTP request is copy-pasteable
[ ] Response showing impact included
[ ] Two accounts used (not self-testing)
[ ] CVSS calculated and included
[ ] Fix: 1-2 sentences
[ ] Under 600 words
[ ] Severity matches impact (no overclaiming)
[ ] NEVER used "could potentially"
```
