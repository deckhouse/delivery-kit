# Tasks: lang-pkg-env-vars

**Input**: Design documents from `/specs/013-lang-pkg-env-vars/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, quickstart.md

**Tests**: The examples below include test tasks. Tests ARE included per the feature specification and research plan.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **CLI commands**: `cmd/werf/<domain>/`
- **Business logic**: `pkg/<domain>/`
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/<domain>/`
- **Test helpers**: `test/pkg/`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run TestMyFunc ./pkg/...`
- **Formatting**: `task format`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and branch setup

- [ ] T001 Create feature branch `013-lang-pkg-env-vars` from main

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Wire the `packages[].env` field into all 9 language package manager `InstallCmd` functions — the core mechanical change that ALL user stories depend on.

**⚠️ CRITICAL**: No user story can be tested until this phase is complete.

### Implementation for Phase 2

**Mechanism**: In `pkg/config/packages_directive.go`, replace `_ map[string]string` with `env map[string]string` and prepend `formatEnvVars(env)` (the existing helper in `packages_commands.go`) when `env` is non-empty.

All 9 tasks are marked `[P]` — they modify different functions in the same file but have no logical dependencies on one another.

- [ ] T002 [P] Wire `env` into `GoMod.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `go mod download` command when env is non-empty
- [ ] T003 [P] Wire `env` into `PythonUV.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `uv sync --frozen` command when env is non-empty
- [ ] T004 [P] Wire `env` into `PythonPip.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `pip install --no-cache-dir -r <spec>` command when env is non-empty
- [ ] T005 [P] Wire `env` into `PythonPoetry.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `poetry sync --no-root` command when env is non-empty
- [ ] T006 [P] Wire `env` into `RustCargo.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `cargo fetch` command when env is non-empty
- [ ] T007 [P] Wire `env` into `JavaScriptNpm.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `npm ci` command when env is non-empty
- [ ] T008 [P] Wire `env` into `JavaScriptYarn.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `yarn install --frozen-lockfile` command when env is non-empty
- [ ] T009 [P] Wire `env` into `JavaScriptPnpm.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `pnpm install --frozen-lockfile` command when env is non-empty
- [ ] T010 [P] Wire `env` into `LuaRock.InstallCmd` in `pkg/config/packages_directive.go` — prepend `formatEnvVars(env)` to `luarocks install --only-deps <spec>` command when env is non-empty

**Checkpoint**: Foundation ready — all 9 language types now pass env vars to the package manager process. User story testing can begin.

---

## Phase 3: User Story 1 — Install packages from private registries (Priority: P1) 🎯 MVP

**Goal**: A user sets registry-specific auth environment variables (e.g., `npm_config__authtoken`, `PIP_INDEX_URL`, `CARGO_REGISTRIES_MYREGISTRY_INDEX`) in `packages[].env` and the language package manager authenticates to private registries.

**Independent Test**: Verify that `GeneratePackagesCommands()` produces auth-env-prefixed commands for each language type via unit tests.

### Tests for User Story 1 ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation (before Phase 2)**

- [ ] T011 [P] [US1] Update "ignores env for non-os-pm package types" test in `pkg/config/packages_commands_test.go` to expect env vars in generated commands instead of discarding them (update existing `nonOsPmEntry` DescribeTable entries or replace them)
- [ ] T012 [P] [US1] Add test for GoMod with `GOPROXY=direct` in `pkg/config/packages_commands_test.go` — expect `GOPROXY="direct" cd "/app" && go mod download`
- [ ] T013 [P] [US1] Add test for PythonPip with `PIP_INDEX_URL=http://pypi:8080` in `pkg/config/packages_commands_test.go` — expect `PIP_INDEX_URL="http://pypi:8080" cd "/app" && pip install --no-cache-dir -r "requirements.txt"`
- [ ] T014 [P] [US1] Add test for JavaScriptNpm with `npm_config__authtoken=token` in `pkg/config/packages_commands_test.go` — expect `npm_config__authtoken="token" cd "/app" && npm ci`
- [ ] T015 [P] [US1] Add test for JavaScriptYarn with `YARN_ENABLE_IMMUTABLE_INSTALLS=false` in `pkg/config/packages_commands_test.go` — expect `YARN_ENABLE_IMMUTABLE_INSTALLS="false" cd "/app" && yarn install --frozen-lockfile`
- [ ] T016 [P] [US1] Add test for JavaScriptPnpm with `PNPM_HOME=/custom/path` in `pkg/config/packages_commands_test.go` — expect `PNPM_HOME="/custom/path" cd "/app" && pnpm install --frozen-lockfile`
- [ ] T017 [P] [US1] Add test for PythonUV with `UV_EXTRA_INDEX_URL=http://pypi:8080` in `pkg/config/packages_commands_test.go` — expect `UV_EXTRA_INDEX_URL="http://pypi:8080" cd "/app" && uv sync --frozen`
- [ ] T018 [P] [US1] Add test for RustCargo with `CARGO_NET_RETRY=3` in `pkg/config/packages_commands_test.go` — expect `CARGO_NET_RETRY="3" cd "/app" && cargo fetch`
- [ ] T019 [P] [US1] Add test for PythonPoetry with `POETRY_HTTP_BASIC_MYREGISTRY_USERNAME=user` in `pkg/config/packages_commands_test.go` — expect `POETRY_HTTP_BASIC_MYREGISTRY_USERNAME="user" cd "/app" && poetry sync --no-root`
- [ ] T020 [P] [US1] Add test for LuaRock with `LUAROCKS_PROXY=http://proxy:8080` in `pkg/config/packages_commands_test.go` — expect `LUAROCKS_PROXY="http://proxy:8080" cd "/app" && luarocks install --only-deps "rockspec"`

### Implementation for User Story 1

The implementation IS Phase 2 (T002–T010). These tests validate that the implementation works for the auth/registry scenario.

- [ ] T021 [US1] Run all Phase 2 + Phase 3 tests and verify they pass: `task test:unit -- paths="./pkg/config/..."`

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently.

---

## Phase 4: User Story 2 — Customize language package manager behavior (Priority: P2)

**Goal**: A user sets configuration env vars (e.g., `PIP_DISABLE_PIP_VERSION_CHECK=1`, `npm_config_cache=/path`) in `packages[].env` and the package manager respects the configuration.

**Independent Test**: Verify backward compatibility — env set to nil or empty produces unchanged commands. Also validate that env vars appear as prefix.

### Tests for User Story 2 ⚠️

- [ ] T022 [US2] Add backward compatibility test: `env` nil/empty produces identical command to pre-feature for all 9 language types in `pkg/config/packages_commands_test.go`
- [ ] T023 [US2] Add test for multiple env vars with alphabetical sorting in `pkg/config/packages_commands_test.go` (verify `formatEnvVars` sorts keys: `A_VAR="a" Z_VAR="z" cd "/app" && command`)

### Implementation for User Story 2

- No additional code changes needed — Phase 2 already implements this.
- [ ] T024 [US2] Run all tests: `task test:unit -- paths="./pkg/config/..."`

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently.

---

## Phase 5: User Story 3 — Proxy support for language package managers (Priority: P3)

**Goal**: A user sets `HTTP_PROXY`/`HTTPS_PROXY` in `packages[].env` and package downloads are routed through the proxy.

**Independent Test**: Verify proxy env vars appear correctly in generated commands for all types.

### Tests for User Story 3 ⚠️

- [ ] T025 [US3] Add test for proxy env vars (`HTTP_PROXY=http://proxy:8080` and `HTTPS_PROXY=https://proxy:8443`) across multiple language types in `pkg/config/packages_commands_test.go` — verify both vars appear as inline prefix

### Implementation for User Story 3

- No additional code changes needed — Phase 2 already implements this.
- [ ] T026 [US3] Run all tests: `task test:unit -- paths="./pkg/config/..."`

**Checkpoint**: All user stories should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Quality gates — format, build, lint

- [ ] T027 [P] Run `task format` to format all modified Go files
- [ ] T028 Run `task build` to verify the binary compiles
- [ ] T029 Run `task lint:golangci-lint golangciPaths="./pkg/config/..."` to verify no linting issues
- [ ] T030 Run full config test suite: `task test:unit -- paths="./pkg/config/..."` to confirm all tests pass

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories proceed sequentially in priority order (P1 → P2 → P3)
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: ALL 9 language types must be wired (Phase 2 complete). Tests verify each type independently — no cross-type dependencies.
- **User Story 2 (P2)**: Depends on Phase 2 completion. Backward compatibility tests are independent of US1 tests.
- **User Story 3 (P3)**: Depends on Phase 2 completion. Proxy tests are independent of US1/US2 tests.

### Within Each User Story

- Tests (if included) MUST be written and FAIL before implementation
- Implementation is Phase 2 (shared foundation, must be complete first)
- Each user story's tests validate the shared implementation from a different angle
- Story complete before moving to next priority

### Parallel Opportunities

- All Phase 2 tasks (T002–T010) can run in parallel — they modify different functions in the same file
- All test tasks within a user story phase (T011–T020, T022–T023, T025) can run in parallel
- Phase 6 polish tasks (T027, T029) can run in parallel

---

## Parallel Example: Phase 2 (Foundational)

```bash
# All 9 InstallCmd wire-ups can be done in parallel:
# (Modify different functions in pkg/config/packages_directive.go)

Task: Wire env into GoMod.InstallCmd
Task: Wire env into PythonUV.InstallCmd
Task: Wire env into PythonPip.InstallCmd
Task: Wire env into PythonPoetry.InstallCmd
Task: Wire env into RustCargo.InstallCmd
Task: Wire env into JavaScriptNpm.InstallCmd
Task: Wire env into JavaScriptYarn.InstallCmd
Task: Wire env into JavaScriptPnpm.InstallCmd
Task: Wire env into LuaRock.InstallCmd
```

## Parallel Example: User Story 1 Tests

```bash
# Launch all US1 tests together:
Task: "task test:unit -- -run TestGoModWithGOPROXY ./pkg/config/"
Task: "task test:unit -- -run TestPythonPipWithPIP_INDEX_URL ./pkg/config/"
Task: "task test:unit -- -run TestJavaScriptNpmWithEnv ./pkg/config/"
# ... one per type
```

## Parallel Example: User Stories (after Phase 2)

```bash
# All user story tests can run in parallel since they share the same source:
Task: "task test:unit -- paths='./pkg/config/'"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (branch creation)
2. Complete Phase 2: Foundational (wire env into all 9 types) — **CRITICAL, blocks everything**
3. Complete Phase 3: User Story 1 (tests for auth env vars)
4. **STOP and VALIDATE**: `task test:unit -- paths="./pkg/config/..."`
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready (all 9 types wired)
2. Add User Story 1 tests + validate → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 tests + validate → Deploy/Demo
4. Add User Story 3 tests + validate → Deploy/Demo
5. Each story adds test coverage without breaking previous stories

### Notes

- **No config schema changes**: The `env` field is already parsed, POSIX-validated, and stored. This feature is purely runtime wiring.
- **All changes are in `pkg/config/`**: No other packages need modification.
- **`formatEnvVars()` helper already exists**: Package-private in `packages_commands.go` — no new utility code needed.
- **The existing "ignores env" test must be updated**: It tests the current behavior (env discarded). After Phase 2, it must test that env vars ARE passed.
- **Single commit strategy**: `feat(config): wire env vars into language package manager install commands`