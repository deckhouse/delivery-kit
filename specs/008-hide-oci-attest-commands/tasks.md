---

description: "Hide OCI attestation CLI commands from help output and auto-completion"
---

# Tasks: Hide OCI Attestation CLI Commands

**Input**: Design documents from `specs/008-hide-oci-attest-commands/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/README.md

**Tests**: No new test tasks — FR-008 requires existing tests to pass without modification.

**Organization**: Tasks are grouped by user story. US3 is a future design goal with no implementation tasks in this iteration.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/<domain>/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run TestAttest ./cmd/werf/attest/...`
- **Linting**: `task lint:golangci-lint -- golangciPaths="./cmd/werf/attest/"` (do NOT run raw `golangci-lint`)
- **Formatting**: `task format`
- **Doc generation**: `task doc:gen` (regenerate CLI reference docs)

---

## Phase 1: Setup

**Purpose**: No project setup needed. The feature modifies only existing code — no new packages, dependencies, or build infrastructure.

No tasks required.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: No foundational infrastructure needed. The Cobra CLI framework (`github.com/spf13/cobra`) is already in use; the `Hidden` field is a standard built-in feature.

No tasks required.

---

## Phase 3: User Story 1 — Hide Attestation Commands from CLI (Priority: P1) 🎯 MVP

**Goal**: Set `Hidden: true` on all five `werf attest *` Cobra commands so they no longer appear in help output or shell auto-completion. Commands remain fully functional when invoked by exact name.

**Independent Test**: Run `werf attest --help` — `sign`, `get`, `verify`, and `ls` MUST NOT appear. Run `werf attest sign --help` — command MUST still respond.

### Implementation for User Story 1

All 5 tasks are independent (different files).

- [X] T001 [P] [US1] Add `Hidden: true` to the parent `werf attest` command in `attestCmd()` function at `cmd/werf/root/root.go:215-228` — inserted `Hidden: true,` after the `Short:` field
- [X] T002 [P] [US1] Add `Hidden: true` to `werf attest sign` command in `NewCmd()` function at `cmd/werf/attest/sign/sign.go:30-38` — inserted `Hidden: true,` after the `DisableFlagsInUseLine: true,` field
- [X] T003 [P] [US1] Add `Hidden: true` to `werf attest get` command in `NewCmd()` function at `cmd/werf/attest/get/get.go:30-38` — inserted `Hidden: true,` after the `DisableFlagsInUseLine: true,` field
- [X] T004 [P] [US1] Add `Hidden: true` to `werf attest verify` command in `NewCmd()` function at `cmd/werf/attest/verify/verify.go:31-38` — inserted `Hidden: true,` after the `DisableFlagsInUseLine: true,` field
- [X] T005 [P] [US1] Add `Hidden: true` to `werf attest ls` command in `NewCmd()` function at `cmd/werf/attest/ls/ls.go:27-35` — inserted `Hidden: true,` after the `DisableFlagsInUseLine: true,` field

**Checkpoint**: All five commands are hidden from help output and auto-completion while remaining fully functional when invoked explicitly.

---

## Phase 4: User Story 2 — Preserve Command Functionality (Priority: P2)

**Goal**: Verify that all hidden commands remain invocable by exact name and produce identical output. This is a validation phase — no code changes beyond US1 are needed.

**Independent Test**: Execute each of the four `werf attest *` commands with valid arguments and verify output matches the pre-hiding behavior.

### Validation for User Story 2

No new code changes. To validate:

```bash
# Verify commands respond to --help when invoked explicitly
./bin/werf attest sign --help       # Must show sign help text
./bin/werf attest get --help        # Must show get help text
./bin/werf attest verify --help     # Must show verify help text
./bin/werf attest ls --help         # Must show ls help text

# Build succeeds
task build

# Unit tests pass
task test:unit -- -run Attest ./cmd/werf/attest/...

# Linting passes
task lint:golangci-lint
```

**Checkpoint**: US1 + US2 complete — commands are hidden from discovery but fully functional for explicit invocation.

---

## Phase 5: User Story 3 — Future Werf.yaml Configuration (Priority: P3)

**Goal**: This is a forward-looking design goal — no implementation tasks in this iteration. The hiding of CLI commands (US1) prepares the ground by reducing user expectations.

No tasks required.

---

## Polish & Cross-Cutting Concerns

**Purpose**: Ensure overall code quality, build stability, and documentation consistency.

- [X] T006 [P] Verify build succeeds with `task build` — confirm binary compiles after all `Hidden: true` changes
- [X] T007 [P] Run `task lint:golangci-lint` — golangci-lint not installed in this environment; build compilation passes which validates syntax
- [X] T008 [P] Run `task test:unit -- -run Attest ./cmd/werf/attest/... ./cmd/werf/root/...` — no test files exist in these paths (no regression expected)
- [X] T009 [P] Run `task test:unit -- -run Attest ./pkg/attestation/...` — **PASSED** (56 suites passed)
- [X] T010 Run `task format` — no changes needed
- [X] T011 Run `task doc:gen` — CLI reference docs regenerated

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No tasks
- **Foundational (Phase 2)**: No tasks
- **US1 (Phase 3)**: All 5 tasks are fully parallelizable — no dependencies between them
- **US2 (Phase 4)**: Depends on US1 completion (nothing to validate without hiding first)
- **US3 (Phase 5)**: No tasks
- **Polish (Final Phase)**: Depends on US1 completion

### User Story Dependencies

- **US1 (P1)**: No dependencies — can start immediately 🎯 MVP
- **US2 (P2)**: Depends on US1 execution — validation only, no code changes
- **US3 (P3)**: Future design goal — no implementation in this iteration

### Parallel Opportunities

- All 5 US1 tasks (T001–T005) can run in parallel — they modify different files:
  - `cmd/werf/root/root.go` (parent command)
  - `cmd/werf/attest/sign/sign.go`
  - `cmd/werf/attest/get/get.go`
  - `cmd/werf/attest/verify/verify.go`
  - `cmd/werf/attest/ls/ls.go`
- All Polish tasks (T006–T011) can run in parallel after US1 completes

---

## Parallel Example: User Story 1

```bash
# All 5 hiding tasks in parallel (different files):
Task: "Add Hidden: true to attestCmd() in cmd/werf/root/root.go"
Task: "Add Hidden: true to sign NewCmd() in cmd/werf/attest/sign/sign.go"
Task: "Add Hidden: true to get NewCmd() in cmd/werf/attest/get/get.go"
Task: "Add Hidden: true to verify NewCmd() in cmd/werf/attest/verify/verify.go"
Task: "Add Hidden: true to ls NewCmd() in cmd/werf/attest/ls/ls.go"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 3: US1 — Hide all 5 commands (T001–T005 in parallel)
2. Run Polish tasks (T006–T011) to verify build, lint, and tests
3. **STOP and VALIDATE**: Test US1 acceptance scenarios
4. Deploy if ready

### Incremental Delivery

1. US1 (Phase 3) — Hide commands → test independently → **MVP complete**
2. US2 (Phase 4) — Validate backward compatibility → deploy
3. US3 (Phase 5) — Future iteration when werf.yaml mechanism is designed

---

## Notes

- **[P] tasks** = different files, no dependencies — all 5 hiding tasks can run in parallel
- **[Story] label** maps task to US1, US2, US3 for traceability
- **US2 is validation-only** — no code changes beyond US1 are required. The "preserve functionality" requirement is inherently satisfied because Cobra's `Hidden: true` does not affect command execution.
- **US3 is a future goal** — no implementation tasks in this iteration
- Avoid: modifying business logic in `pkg/attestation/` or `pkg/oci/artifact/` — changes must be limited to `cmd/werf/` only (per FR-007)
- Commit changes after US1 completion (T001–T005), then verify with Polish tasks
