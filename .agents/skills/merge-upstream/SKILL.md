---
name: merge-upstream
description: Merge werf upstream into the deckhouse/delivery-kit fork. Resolves conflicts (CHANGELOG.md kept -dk-only), then opens a PR for review. Use when asked to sync upstream into delivery-kit.
---

# Merge Upstream (werf → delivery-kit)

## Context

- **Upstream** = `werf/werf` (fetch/merge source). **Fork** = `deckhouse/delivery-kit` (push target).
- Remote names vary per clone, so Step 0 resolves both by URL into `$UPSTREAM` / `$FORK`.
- `CHANGELOG.md` is release-please-managed (`release-type: go`, runs on push to `main`).
  Nothing from `upstream/main` ever lands in it: on conflict you always take ours and never copy,
  author, or prepend any entry — the changelog is release-please's job on push to `main`, not the
  agent's. The agent only pins the release version via an empty `Release-As` commit (Step 2).
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

Suffix the branch (`-2`, …) if it already exists. Work only on this branch. `--no-ff -m` keeps the
merge subject identical with or without conflicts.

Resolve conflicts:

- **`CHANGELOG.md`** — always take ours: `git checkout --ours CHANGELOG.md && git add CHANGELOG.md`.
  Upstream changelog changes are dropped. Do NOT author or prepend any entry — release-please
  generates the changelog on push to `main`.
- **`go.mod` / `go.sum`** — resolve obvious parts, then `go mod tidy && git add go.mod go.sum`.
  Never blindly take one side.
- **Any other file** — do not blanket-take upstream; it can silently revert delivery-kit
  customizations (branding, `d8 dk` wiring, module path). Stop and surface the conflict for a
  maintainer.

Stage resolved tracked files only, then commit:

```bash
git add -u && git commit --no-edit
```

### 2. Force the release version (no changelog)

Do NOT author or prepend anything in `CHANGELOG.md` — release-please generates it on push to
`main`. The only release artifact the agent adds is an empty `Release-As` commit that pins the
version to the upstream base being merged.

Fork versions are `<upstream semver>-dk.<N>`: the base is exactly the werf version merged in Step 1,
`N` starts at 1 for each new base. So if this merge brings upstream `2.76.0`, the version is
`2.76.0-dk.1` — never a base werf never released. Releases made between upstream merges (fork-side
fixes only) need no commit here: `release_release-please.yml` increments `N` from
`.release-please-manifest.json` on its own, and skips that when it sees a `Release-As:` footer.

```bash
git commit --allow-empty -m "chore: force release X.Y.Z-dk.1

Release-As: vX.Y.Z-dk.1"
```

`Release-As: vX.Y.Z-dk.1` must be in the **commit body** (blank line after subject), not the subject
line. The value must include the `v` prefix.

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
git diff "$FORK/main" -- CHANGELOG.md                                  # MUST be empty (nothing from upstream)
git status                                                             # MUST be clean

git push -u "$FORK" chore/release/merge-werf-upstream
gh pr create --repo deckhouse/delivery-kit --base main \
  --head chore/release/merge-werf-upstream \
  --title "chore(release): merge werf upstream into delivery-kit (X.Y.Z-dk.1)" \
  --body "Sync werf upstream. CHANGELOG.md unchanged; release-please generates it on merge. Release pinned to X.Y.Z-dk.1 via Release-As."
```

The agent stops after opening the PR; a maintainer reviews and merges.

To recover before pushing: `git merge --abort`, or discard the branch with
`git checkout - && git branch -D chore/release/merge-werf-upstream`.

## Rules

- Branch/commit/PR names use the fixed values above; follow the `git-branch-name`,
  `git-commit-message`, and `pull-request-name` skills for any other naming.
- ALWAYS work on the `chore/release/...` branch and finish with a PR; NEVER push to the fork's `main`.
- ALWAYS run `task doc:gen`, `task build`, `task test:unit` before the PR; NEVER open it with a broken build or remaining conflict markers.
- CHANGELOG: NEVER copy, author, prepend, or reorder any entry; take ours (`--ours`) on conflict and leave it byte-identical to `$FORK/main`. The changelog is release-please's job.
- ALWAYS add an empty `Release-As: v<upstream semver>-dk.1` commit (Step 2) so release-please pins the merged upstream base; NEVER invent a base werf has not released, and NEVER author a changelog entry for it — release-please generates the changelog on push to `main`.
- NEVER `git add .`; stage only resolved tracked files.
- NEVER blanket-resolve non-CHANGELOG conflicts toward upstream; stop and ask a human.
