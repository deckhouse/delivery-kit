---
name: review-tech
description: Technical code review for changes in the Deckhouse Delivery Kit. Evaluates Go, werf, Docker, Container Registry, and nelm code against SOLID/DRY/KISS principles and project conventions. Use when asked to review pull requests, branches, or code changes.
---

# Technical Review

Review code changes for quality, architecture, and best practices. Focus on what the agent would not know without project context: the specific technology stack (Go, werf, Docker, nelm) and how principles apply to this codebase.

## Gotchas

- This project is built on top of **werf**, which uses [werf/nelm](https://github.com/werf/nelm) as its deployment engine. Do NOT evaluate against generic Helm best practices — evaluate against nelm-specific patterns.
- The project uses **content-based tagging** for container images. Tag logic matters for cache invalidation and registry cleanup.
- **Registry cleanup** is a unique werf feature. Changes to cleanup logic can cause data loss if wrong.
- The `Taskfile.dist.yaml` uses **remote taskfiles**. All build/test commands run through `task`, never raw Go tools.

## Methodology

Evaluate changes against these principles, referencing specific file:line in the diff:

| Principle | What to check |
| :--- | :--- |
| SOLID | SRP per type, OCP for extensibility, ISP for interface size. |
| DRY | Duplicated logic, config, or error handling. |
| KISS/YAGNI | Unnecessary abstraction, generics, or interfaces for hypothetical needs. |
| Security | Least privilege, input validation, secret handling, container security. |
| Observability | Logs/metrics for critical paths, especially deploy and registry operations. |
| Testability | Can the change be tested without mocks or integration setup? |

## Input

The coordinator provides: git diff, codebase analysis, DoD criteria.

## Output format

### Technical Review Summary

[2-3 sentence expert opinion in the user's language]

### Adherence to Best Practices

| Practice | Status | Comments |
| :--- | :--- | :--- |
| SOLID | ✅/⚠️/❌ | file:line — one-liner |
| DRY | ✅/⚠️/❌ | ... |
| KISS/YAGNI | ✅/⚠️/❌ | ... |
| Security | ✅/⚠️/❌ | ... |
| Observability | ✅/⚠️/❌ | ... |
| Testability | ✅/⚠️/❌ | ... |

### DoD Criteria Assessment

| Criteria | Met? | Comments |
| :--- | :--- | :--- |
| [Criterion] | ✅/⚠️/❌ | file:line reference |

### Issues Found

- **Critical**: blocking, with file:line
- **Major**: significant concern
- **Minor**: suggestion

## Constraints

- Issue descriptions in the user's language. Headers in English.
- Reference specific lines. No obvious comments.