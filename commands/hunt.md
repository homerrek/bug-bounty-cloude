---
description: Start hunting on a target — loads scope, reads disclosed reports, picks best attack surface based on tech stack, runs targeted vuln checks. Usage: /hunt target.com [--vuln-class ssrf|idor|xss|sqli|oauth|race|graphql|llm|upload|business-logic]
---

# /hunt

Active vulnerability hunting on a target.

> Ref: `skills/bug-bounty/SKILL.md` (full testing methodology, A→B chain table, tech stack → vuln class mapping)

## Usage

```
/hunt target.com
/hunt target.com --vuln-class idor
/hunt target.com --vuln-class ssrf
/hunt target.com --vuln-class graphql
/hunt target.com --source-code   (if repo is available)
```

## Phase 1: Read Before Touching (15 min)

1. Read program scope — every in-scope domain, every exclusion, excluded bug classes, safe harbor
2. Read disclosed reports: `https://hackerone.com/TARGET_NAME/hacktivity`
   - Extract: endpoint, bug class, parameter, missing check, payout

## Phase 2: Tech Stack Detection (2 min)

```bash
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"
```

Stack → Primary bug class:
- Ruby on Rails → mass assignment, IDOR
- Django → IDOR (ModelViewSet), SSTI
- Flask → SSTI, SSRF
- Express/Node → prototype pollution, path traversal
- Spring Boot → Actuator endpoints, SSTI
- Next.js → SSRF via Server Actions
- GraphQL → introspection, IDOR via node(), auth bypass on mutations

## Phase 3: Active Testing

Run targeted tests for highest-ROI bug classes based on tech stack. See `skills/bug-bounty/SKILL.md` for detailed testing methodology for each bug class (IDOR, auth bypass, SSRF, GraphQL, XSS, race conditions, OAuth, SQLi, file upload, business logic, LLM).

## Phase 4: A→B Signal Method

When you confirm bug A → stop → check for B and C before writing the report.
See `skills/bug-bounty/SKILL.md` for the full A→B chain table.

Rules: Confirm A is real first. B must be different bug. B must pass Gate 0 independently.

## Phase 5: Document Findings

Create `targets/<target>/SESSION.md`:
```markdown
# TARGET: target.com | DATE: [today] | CROWN JEWEL: [what attacker wants most]

## Active Leads
- [14:22] /api/v2/invoices/{id} — no ownership check visible. Testing...

## Dead Ends (don't revisit)
- /admin → IP restricted.

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} — read+write from attacker session
```

## Rotation Rules

- Every 20 min: "Am I making progress?" No → rotate to next endpoint or vuln class.
- Stop signals: 403 no matter what, 20+ payload variations identical response, finding needs 5+ preconditions.
