---
name: merge-upstream
description: Merge werf upstream (origin/main) into deckhouse/delivery-kit fork (dk-main). Resolves CHANGELOG.md conflicts by keeping -dk entries only. Use when given a delivery-kit PR URL or asked to merge upstream changes.
---

# Merge Upstream (werf → delivery-kit)

## Context

- **Fork:** `deckhouse/delivery-kit` (remote `delivery-kit`, branch `main`)
- **Upstream:** `werf/werf` (remote `origin`, branch `main`)
- **Local tracking branch:** `dk-main` → tracks `delivery-kit/main`
- **CHANGELOG rule:** only `-dk` versioned entries belong in `CHANGELOG.md`. Never add bare upstream entries like `## [2.72.2]` — only `## [2.72.2-dk]`.

## Steps

### 1. Resolve changelog for the PR

Given a PR URL (e.g. `https://github.com/deckhouse/delivery-kit/pull/NNN`):

1. Fetch PR contents via `webfetch`.
2. Identify all meaningful commits (skip `chore(main): release X.Y.Z` release-please commits and `chore(release): N alpha,beta` commits).
3. Determine the next `-dk` version: look at the top of `CHANGELOG.md`, increment the patch of the latest `-dk` tag.
4. Add a new `-dk` entry at the top of `CHANGELOG.md` (below `# Changelog`) with today's date.
   - Include `### Features` and/or `### Bug Fixes` sections as appropriate.
   - Use `deckhouse/delivery-kit` issue/commit links, not `werf/werf` links.
   - Never add a bare upstream block (`## [X.Y.Z]` without `-dk`).
5. Commit: `chore(release): resolve changelog for X.Y.Z-dk`

### 2. Merge upstream into dk-main

```bash
git fetch origin main
git merge origin/main --no-edit
```

If conflicts arise, resolve them:

**CHANGELOG.md conflicts:**
- Keep the `-dk` block from HEAD.
- Discard the bare upstream block from `origin/main` (the `<<<<<<< HEAD` / `>>>>>>> origin/main` markers around `## [X.Y.Z]` without `-dk`).
- Result: `-dk` entry at top, followed by the rest of the existing `-dk` history. No bare upstream entries added.

**Other file conflicts:** resolve by taking `origin/main` version unless the file contains delivery-kit–specific customizations (check git blame / prior `-dk` commits).

After resolving all conflicts:
```bash
git add .
git commit -m "chore(main): merge werf main into dk-main"
```

### 3. Push and merge PR

```bash
git push delivery-kit dk-main:main
```

If the PR still shows as not mergeable after push (conflict was on the PR side), the push itself resolves it — the PR is superseded by the direct push to `main`.

## Commit messages

- Changelog resolution: `chore(release): resolve changelog for X.Y.Z-dk`
- Merge commit: `chore(main): merge werf main into dk-main`

## Rules

- NEVER add bare upstream changelog entries (e.g. `## [2.72.2]`). Only `-dk` entries in `CHANGELOG.md`.
- NEVER modify `CHANGELOG.md`, release notes, or generated files beyond what's described here.
- NEVER commit unless changes are staged and verified conflict-free.
- When resolving CHANGELOG conflicts: always prefer HEAD (`-dk` block) over `origin/main` (bare block).
