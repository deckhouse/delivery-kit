---
name: merge-upstream-lite
description: Merge werf upstream into the deckhouse/delivery-kit fork — works in the current branch, asks for upstream reference, and hands off remaining conflicts to a human. Use when you need a lightweight interactive merge.
---

# Merge Upstream Lite (werf → delivery-kit)

## Context

- **Upstream** = `werf/werf` (fetch/merge source). **Fork** = `deckhouse/delivery-kit` (push target).
- Remote names vary per clone, so Step 0 resolves both by URL into `$UPSTREAM` / `$FORK`.
- Requires a clean working tree.
- Unlike the full `merge-upstream` skill, this skill:
  - Works in the **current branch** (no new branch creation).
  - Asks the user which upstream reference to merge (branch or tag).
  - **Merges upstream Features and Bug Fixes entries into the current `-dk` version section** of CHANGELOG.md instead of dropping them or adding new version sections.
  - Stops after building and verifying — no PR is opened.

The agent asks the user for the upstream reference, displays the plan, and proceeds step by step, printing progress at each step.

## Plan

### Overview

The merge is broken into 4 phases with 9 steps total:

| # | Phase | Steps | What happens |
|---|-------|-------|-------------|
| 1 | Fetch | 1/9 | Fetch the requested upstream reference |
| 2 | Merge | 2–4/9 | Merge upstream, auto-resolve CHANGELOG.md, hand off remaining conflicts to the user, and commit |
| 3 | Update | 5–7/9 | Update Go dependencies, regenerate docs, and commit resulting changes |
| 4 | Verify | 8–9/9 | Check for leftover conflict markers and build |

### Progress display

Before starting, the agent prints the plan overview above.

Then, at each step, the agent prints:

```
[Step N/9 — Phase M/4: PhaseName] Description of what is happening
```

After each completed step, the agent prints:

```
✓ Step N/9 complete
```

---

## Steps

### 0. Resolve remotes by URL

Map each repo to whatever remote points at it, adding the upstream if missing. Run in the same shell as the later steps so `$UPSTREAM` / `$FORK` stay set:

```bash
UPSTREAM=$(git remote -v | awk '/werf\/werf(\.git)? \(fetch\)/{print $1; exit}')
FORK=$(git remote -v | awk '/deckhouse\/delivery-kit(\.git)? \(fetch\)/{print $1; exit}')
[ -n "$UPSTREAM" ] || { git remote add upstream https://github.com/werf/werf.git; UPSTREAM=upstream; }
[ -n "$FORK" ]     || { echo "no remote for deckhouse/delivery-kit"; exit 1; }
```

Then ask the user: **"Which upstream reference would you like to merge? (e.g., `main`, `v2.73.0`, `releases/2.72`)"**.

Store the answer in `$UPSTREAM_REF`.

If the answer is empty, default to `main`.

### 1. Fetch — Step 1/9

Print:

```
[Step 1/9 — Phase 1/4: Fetch] Fetching upstream reference "$UPSTREAM/$UPSTREAM_REF" and fork
```

```bash
git fetch "$UPSTREAM" "$UPSTREAM_REF"
git fetch "$FORK"
```

After completion, print:

```
✓ Step 1/9 complete
```

### 2. Merge — Steps 2–4/9

Print:

```
[Step 2/9 — Phase 2/4: Merge] Previewing incoming commits
```

First, show the user a preview of what will be brought in:

```bash
git log --oneline "$UPSTREAM/$UPSTREAM_REF" "^$FORK/main"
```

Then ask the user: **"Merge `$UPSTREAM/$UPSTREAM_REF` into the current branch? (yes/no)"**.

- If "no" (or anything other than explicit "yes"), stop and tell the user to re-run when ready.
- If "yes", proceed.

```bash
git merge --no-ff -m "chore(dev): merge werf upstream into delivery-kit" "$UPSTREAM/$UPSTREAM_REF"
```

```
✓ Step 2/9 complete
```

#### 2.1 Auto-resolve CHANGELOG.md conflicts (Step 3/9)

Print:

```
[Step 3/9 — Phase 2/4: Merge] Auto-resolving CHANGELOG.md conflicts
```

If CHANGELOG.md has conflicts, resolve them as follows.

**Important**: delivery-kit and werf CHANGELOG.md structures differ — werf uses plain semver (`2.77.0`), delivery-kit uses `-dk` suffix (`2.77.0-dk`). The goal is to **merge upstream entries into the current -dk version**, not to add new version sections. Only Features and Bug Fixes sections from upstream matter; ignore all other sections.

1. **Read the current branch's CHANGELOG.md** — the delivery-kit side. During a merge conflict, the delivery-kit version is stored in stage 2 (ours). Use:

   ```bash
   git show :2:CHANGELOG.md
   ```

2. **Read the upstream's CHANGELOG.md** — the werf incoming version. During a merge conflict, the werf version is stored in stage 3 (theirs). Use:

   ```bash
   git show :3:CHANGELOG.md
   ```

3. **Merge upstream entries into the current -dk version**:

   a. Take the delivery-kit CHANGELOG.md as base.
   b. Identify the **current `-dk` version** — the first version section at the top of the delivery-kit file (e.g. `## [2.77.0-dk]`).
   c. Extract **all** `### Features` and `### Bug Fixes` entries from **all** werf version sections in the incoming upstream file. Ignore:
      - Werf version headers (`## [x.y.z]`)
      - Any sections other than Features and Bug Fixes
      - Empty sections
   d. Insert extracted upstream entries under the corresponding sections of the **current `-dk` version**.

      Example: if upstream brings `v2.77.0` (Features: A) and `v2.76.1` (Bug Fixes: B), and current dk version is `v2.77.0-dk` (Features: C, Bug Fixes: D), the result is:

      ```markdown
      ## [2.77.0-dk](...)

      ### Features

      * C
      * A

      ### Bug Fixes

      * D
      * B
      ```

4. **Before showing the result**, print the delta:
   - **What changed (delta)**: Show all upstream Features and Bug Fixes entries that are being merged into the `-dk` version.
   - **Final result**: Print the resulting merged CHANGELOG.md content.

5. Write the final merged content to CHANGELOG.md and stage it:

```bash
git add CHANGELOG.md
```

```
✓ Step 3/9 complete
```

#### 2.2 Hand over remaining conflicts to the user (Step 4/9)

Print:

```
[Step 4/9 — Phase 2/4: Merge] Checking for remaining conflicts
```

Check for any remaining conflicted files:

```bash
git diff --name-only --diff-filter=U
```

If there are remaining conflicts, print them and hand over to the user:

```
Conflicts remain in the following files:
  <file1>
  <file2>
  ...

Please resolve them manually. Once done, stage and commit the resolution.
The agent will continue from Step 5 once you confirm (yes/no).
```

Wait for the user to confirm conflicts are resolved before proceeding.

```
✓ Step 4/9 complete
```

#### 2.3 Commit merged changes

```bash
git add -u && git commit --no-edit
```

### 3. Update — Steps 5–7/9

#### 3.1 `go mod tidy` (Step 5/9)

Print:

```
[Step 5/9 — Phase 3/4: Update] Running go mod tidy
```

```bash
go mod tidy
```

If `go.mod` or `go.sum` changed, stage them (do NOT commit yet).

```
✓ Step 5/9 complete
```

#### 3.2 Regenerate docs (Step 6/9)

Print:

```
[Step 6/9 — Phase 3/4: Update] Regenerating docs
```

```bash
task doc:gen
```

```
✓ Step 6/9 complete
```

#### 3.3 Commit if changes exist (Step 7/9)

Print:

```
[Step 7/9 — Phase 3/4: Update] Committing update changes
```

If files changed after `go mod tidy` / `task doc:gen`, commit everything:

```bash
git add -u && git commit -m "chore(dev): actualize after werf upstream merge"
```

If no files changed, print "Nothing to commit — working tree clean." and continue.

```
✓ Step 7/9 complete
```

### 4. Verify — Steps 8–9/9

#### 4.1 Check for conflict markers (Step 8/9)

Print:

```
[Step 8/9 — Phase 4/4: Verify] Checking for leftover conflict markers
```

```bash
git grep -q '^<<<<<<<' && { echo "ABORT: conflict markers found in:"; git grep -l '^<<<<<<<'; exit 1; } || echo "OK: no conflict markers"
```

```
✓ Step 8/9 complete
```

#### 4.2 Build (Step 9/9)

Print:

```
[Step 9/9 — Phase 4/4: Verify] Building
```

```bash
task build
```

If build fails, stop and alert the user.

```
✓ Step 9/9 complete
```

If all checks pass:

```
All 9 steps complete. Merge of "$UPSTREAM/$UPSTREAM_REF" into current branch is done.
```

## Rules

- ALWAYS ask the user for the upstream reference before fetching.
- ALWAYS display the plan with total step count and current step number before each action.
- ALWAYS ask permission before merging into the current branch.
- ALWAYS handle CHANGELOG.md by merging upstream Features and Bug Fixes entries into the current `-dk` version section — never add new werf version sections, never blindly take `--ours` or `--theirs`. Ignore werf version headers and non-Features/Bug Fixes sections.
- ALWAYS print the CHANGELOG.md delta before and the final result after resolution.
- ALWAYS hand off remaining conflicts to the user after CHANGELOG.md is resolved.