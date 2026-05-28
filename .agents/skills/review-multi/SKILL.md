---
name: review-multi
description: Multi-role code review for the Deckhouse Delivery Kit. Orchestrates technical, product, and risk analysis roles into a single consolidated report. Use when asked to do a full review of a pull request, branch, or code changes.
---

# Multi-Role Code Review

Orchestrate a multi-role code review of changes in the Deckhouse Delivery Kit project. Three reviewer roles — technical, product, and risk — each evaluate the changes from their perspective. Follow the workflow below, loading the specialist skills (review-tech, review-product, review-risk) for the detailed methodology of each role.

## Workflow

### Phase 1: Preparation

1. Ask the user for DoD (Definition of Done) — numbered acceptance criteria that all reviewers will use to evaluate the changes.
2. Obtain `git diff main...HEAD` to see the changes introduced in the current branch.
3. Analyze the diff: identify modified files, type of change (feature/fix/refactor/docs), patterns, and areas of concern.
4. Perform deep analysis of the affected code: read the changed files and their consumers, search for symbol usages, understand the context of changed packages.

### Phase 2: Technical Reviewer Role

Activate the **Technical Reviewer** role using the **review-tech** skill. Evaluate code quality, architecture, and adherence to best practices. Provide the skill with the git diff, codebase analysis, and DoD criteria.

### Phase 3: Product Reviewer Role

Activate the **Product Reviewer** role using the **review-product** skill. Evaluate DoD alignment, user impact, completeness, and product consistency. Provide the skill with the git diff, codebase analysis, and DoD criteria.

### Phase 4: Risk Analyst Role

Activate the **Risk Analyst** role using the **review-risk** skill. Identify technical, security, UX, and operational risks. Provide the skill with the git diff, codebase analysis, DoD criteria, and the findings from both the Technical Reviewer and Product Reviewer.

### Phase 5: Final Report

1. Determine the current git branch name.
2. Combine all findings into a single risk analysis table. Use the risk analyst's table as the base and enrich it with context from the technical and product reviews — add new risks, merge related ones, and ensure all concerns from all phases are captured. Every row must have a specific location.
3. Assemble the final report with this structure, then save to `reviews/<branch-name>/REVIEW.md`:

```markdown
## Expert Opinions
- Technical Reviewer: [2-3 sentence key finding in the user's language]
- Product Reviewer: [2-3 sentence key finding in the user's language]
- Risk Analyst: [2-3 sentence key finding in the user's language]

## Risk Analysis Table
| Risk | Type | Probability | Location | Circumstances | Consequences |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ... | Technical/UX/Security/Operational | Low/Medium/High | file:line or component | (User Language) | (User Language) |
```

## Gotchas

- **werf** uses [werf/nelm](https://github.com/werf/nelm) as its deployment engine — evaluate against nelm-specific patterns, not generic Helm.
- **Content-based tagging** is used for container images. Tag logic affects cache invalidation and registry cleanup.
- **Registry cleanup** is a unique werf feature. Changes to cleanup logic can cause data loss. Users rely on dry-run modes.
- The `Taskfile.dist.yaml` uses **remote taskfiles**. All build/test commands run through `task`, never raw Go tools.
- werf is a **CLI tool** — command-line UX, error messages, and help text are part of the product.
- nelm is an **engine, not a standalone tool** — changes to nelm behavior affect all werf deployments.
- The **risk analysis table** is the final summary. Do NOT add prose after it.

## Language Rules

- Communicate with the user in their language (e.g., Russian if they write in Russian).
- Report headers MUST be in English.
- The Circumstances and Consequences columns in the risk table MUST be in the user's language.