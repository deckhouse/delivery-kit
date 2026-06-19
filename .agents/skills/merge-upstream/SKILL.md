---
name: merge-upstream
description: Merge werf upstream into the deckhouse/delivery-kit fork. Resolves conflicts (CHANGELOG.md kept -dk-only), then opens a PR for review. Use when asked to sync upstream into delivery-kit.
---

# Merge Upstream (werf → delivery-kit)

## Context

- **Upstream** = `werf/werf` (fetch/merge source). **Fork** = `deckhouse/delivery-kit` (push target).
- Remote names vary per clone, so Step 0 resolves both by URL into `$UPSTREAM` / `$FORK`.
- `CHANGELOG.md` is release-please-managed (`release-type: go`, runs on push to `main`). Only `-dk`
  entries are authored by hand; bare upstream blocks (`## [X.Y.Z]`) already in history stay, but
  you never add new ones.
- Requires `gh` authenticated and a clean working tree.

The agent merges, resolves conflicts, and opens a PR — it never pushes to the fork's `main`.

## Steps

### 0. Resolve remotes by URL

Map each repo to whatever remote points at it, adding the upstream if missing. Run in the same shell
as the later steps so `$UPSTREAM` / `$FORK` stay set:

```bash
UPSTREAM=$(git remote -v | awk '/werf\/werf(\.git)? \(fetch\)/{print $1; exit}')
FORK=$(git remote -v | awk '/deckhouse\/delivery-kit(\.git)? \(fetch\)/{print $1; exit}')
[ -n "$UPSTREAM" ] || { git remote add upstream https://github.com/werf/werf.git; UPSTREAM=upstream; }
[ -n "$FORK" ]     || { echo "no remote for deckhouse/delivery-kit"; exit 1; }
git fetch "$UPSTREAM" && git fetch "$FORK"
```

### 1. Branch off the fork's main and merge upstream

```bash
git checkout -b chore/release/merge-werf-upstream "$FORK/main"
git log --oneline "$UPSTREAM/main" "^$FORK/main"   # preview what gets pulled in
git merge --no-ff -m "chore(release): merge werf upstream into delivery-kit" "$UPSTREAM/main"
```

Branch name follows the werf convention `<type>/<scope>/<short-description>` (top-level scope,
≤ 50 chars). Suffix it (`-2`, …) if it already exists. Work only on this branch. `--no-ff -m` keeps
the merge subject identical with or without conflicts.

Resolve conflicts:

- **`CHANGELOG.md`** — always take ours: `git checkout --ours CHANGELOG.md && git add CHANGELOG.md`.
  Upstream changelog changes are dropped; the `-dk` entry is authored in Step 2.
- **`go.mod` / `go.sum`** — resolve obvious parts, then `go mod tidy && git add go.mod go.sum`.
  Never blindly take one side.
- **Any other file** — do not blanket-take upstream; it can silently revert delivery-kit
  customizations (branding, `d8 dk` wiring, module path). Stop and surface the conflict for a
  maintainer.

Stage resolved tracked files only, then commit:

```bash
git add -u && git commit --no-edit
```

### 2. Author the `-dk` changelog entry

Do this after a conflict-free merge exists. Use the Step 1 preview for the commit list (and
`gh pr view <url> --json commits` if a delivery-kit PR URL was given).

Skip release-please noise (`chore(main): release …`, `chore(release): N alpha,beta`).

Pick the next `-dk` version **from the upstream base being merged**: if upstream moved
`2.72.x → 2.73.0`, it is `2.73.0-dk`; if the upstream base is unchanged and you add only fork-side
fixes, bump the `-dk` patch. Never blindly +1 the latest `-dk` patch across an upstream minor/major.

Prepend one block below `# Changelog` (today's date), then commit:

```
## [X.Y.Z-dk](https://github.com/deckhouse/delivery-kit/compare/vPREV-dk...vX.Y.Z-dk) (YYYY-MM-DD)
### Features / Bug Fixes — using deckhouse/delivery-kit links, not werf/werf
```

```bash
git add CHANGELOG.md && git commit -m "chore(release): resolve changelog for X.Y.Z-dk"
```

### 3. Regenerate docs, build, test

An upstream merge can change CLI flags/help and break the build:

```bash
task doc:gen          # commit changes as: docs(dev): regenerate after werf upstream merge
task build            # MUST succeed
task test:unit        # MUST pass
```

If build or tests fail, stop and resolve (or surface for a maintainer) before the PR.

### 4. Verify, push the branch, open the PR

```bash
git grep -q '^<<<<<<<' && { echo "ABORT: conflict markers"; exit 1; }  # MUST find none
head -5 CHANGELOG.md                                                   # top MUST be the new -dk block
git status                                                             # MUST be clean

git push -u "$FORK" chore/release/merge-werf-upstream
gh pr create --repo deckhouse/delivery-kit --base main \
  --head chore/release/merge-werf-upstream \
  --title "chore(release): merge werf upstream into delivery-kit (X.Y.Z-dk)" \
  --body "Sync werf upstream. CHANGELOG.md kept -dk-only. New release entry: X.Y.Z-dk."
```

The agent stops after opening the PR; a maintainer reviews and merges.

To recover before pushing: `git merge --abort`, or discard the branch with
`git checkout - && git branch -D chore/release/merge-werf-upstream`.

## Rules

- ALWAYS work on a `chore/release/merge-werf-upstream` branch and finish with a PR; NEVER push to the fork's `main`.
- ALWAYS name branches/commits/PRs per the werf convention (`<type>/<scope>/<desc>`, `<type>(<scope>): <subject>`, ≤ 72 chars).
- ALWAYS run `task doc:gen`, `task build`, `task test:unit` before the PR; NEVER open it with a broken build or remaining conflict markers.
- CHANGELOG: NEVER add a bare upstream block or reorder existing entries; only prepend one `-dk` block, and take ours (`--ours`) on conflict.
- NEVER `git add .`; stage only resolved tracked files.
- NEVER blanket-resolve non-CHANGELOG conflicts toward upstream; stop and ask a human.
