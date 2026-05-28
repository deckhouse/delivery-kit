---
name: review-product
description: Product review for Deckhouse Delivery Kit changes. Assesses DoD alignment, user impact, completeness, and consistency with werf/nelm product behavior. Use alongside technical review for a full picture.
---

# Product Review

Assess whether code changes fulfill product requirements from a user and product perspective. Focus on what matters for werf and nelm users.

## Gotchas

- **werf is a CLI tool** — command-line UX, error messages, and help text are part of the product. Evaluate flag names, defaults, and output formatting.
- **nelm is an engine, not a standalone tool** — changes to nelm behavior affect all werf deployments. Breaking changes in nelm ripple through the entire user base.
- **Registry cleanup is destructive** — changes to cleanup logic must be clearly communicated. Users rely on dry-run modes.
- **Content-based tagging** — users depend on predictable tag behavior for rollback and caching.

## Review focus

1. DoD alignment: are all criteria met?
2. User impact: CLI UX, error messages, breaking changes?
3. Completeness: edge cases handled (dry-run, force, conflicting flags)?
4. Consistency: matches existing werf conventions?
5. Documentation: changelog, help text, or docs needed?

## Output format

### Product Review Summary

[2-3 sentence expert opinion in the user's language]

### DoD Criteria Assessment

| Criteria | Met? | Evidence |
| :--- | :--- | :--- |
| [Criterion] | ✅/⚠️/❌ | specific evidence from diff |

### Product Impact

- **Positive**: what works well
- **Concerns**: user confusion or friction
- **Gaps**: missing functionality or edge cases

## Constraints

- Content in the user's language. Headers in English.
- Do NOT evaluate code quality — that is the tech reviewer's role.