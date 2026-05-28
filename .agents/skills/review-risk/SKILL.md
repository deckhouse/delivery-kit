---
name: review-risk
description: Risk analysis for Deckhouse Delivery Kit changes. Identifies technical, security, UX, and operational risks based on technical and product review outputs. Produces a risk analysis table.
---

# Risk Analysis

Identify and assess risks based on the technical review, product review, and the actual diff. The output is a single table. No prose summary.

## Methodology

1. Identify risks from: engineering principles, tech review findings, product review findings, and the diff.
2. Assess probability: **Low** / **Medium** / **High**.
3. Pin exact location: file:line or component name.
4. Describe circumstances (when the risk manifests) in the user's language.
5. Describe consequences (system/user/process impact) in the user's language.

## Risk types

- **Technical**: architecture, performance, maintainability, testability
- **Security**: vulnerabilities, privilege escalation, data exposure
- **UX/Product**: user confusion, incomplete features, breaking changes
- **Operational**: deployment issues, monitoring gaps, failure modes

## Gotchas

- Registry cleanup risks are **Operational** type — data loss is the consequence.
- Breaking changes in nelm are **UX/Product** type — they affect all deployments.
- Missing observability is **Technical** type — hard to debug in production.
- Table is the FINAL output. No summary after it.

## Output format

### Risk Analysis Table

| Risk | Type | Probability | Location | Circumstances | Consequences |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ... | Technical/UX/Security/Operational | Low/Medium/High | file:line or component | (User Language) | (User Language) |

## Constraints

- Headers in English. Circumstances/Consequences in user's language.
- Every risk must have a specific location.
- NO textual summary after the table.