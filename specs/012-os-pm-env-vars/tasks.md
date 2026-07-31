# Tasks: os-pm-env-vars

**Input**: Design documents from `specs/012-os-pm-env-vars/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Tests are included because the spec defines acceptance scenarios and the plan explicitly requires test updates. Existing tests in `pkg/config/packages_commands_test.go` need updating. All new env var tests prefer `DescribeTable` (table-driven Ginkgo) over individual `It` blocks.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/config/`
- **Unit tests**: co-located with source files as `*_test.go`

## Build & Test Commands

- **Build**: `task build`
- **Unit tests (scoped)**: `task test:unit paths="./pkg/config/..."`
- **Formatting**: `task format`
- **Lint**: `task lint:golangci-lint golangciPaths="./pkg/config/..."`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

No setup tasks needed — this is an existing project. The feature branch `012-os-pm-env-vars` is already created.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core data model changes that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T001 Add `Env map[string]string` field with `yaml:"env,omitempty"` tag to `rawPackagesDirective` struct in `pkg/config/raw_packages_directive.go`
- [ ] T002 Add `Env map[string]string` field to `PackagesDirective` struct in `pkg/config/packages_directive.go`
- [ ] T003 Implement POSIX env var name validation (`^[a-zA-Z_][a-zA-Z0-9_]*$`) in `rawPackagesDirective.toDirective()` in `pkg/config/raw_packages_directive.go` — validate each key in `Env`, return error like `invalid environment variable name %q in packages[%d].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*` for invalid names

**Checkpoint**: Foundation ready — user story implementation can now begin

---

## Phase 3: User Story 1 - Install packages from private registry using Docker config secret (P1) 🎯 MVP

**Goal**: Users can set `DOCKER_CONFIG` in `packages[].env` to point to a secrets mount point for private registry authentication.

**Independent Test**: Create a build with a private registry package, mount a Docker config secret, set `DOCKER_CONFIG` env var in the os-pm section, and verify the package installs successfully.

### Implementation for User Story 1

- [ ] T004 [US1] Add `formatEnvVars(env map[string]string) string` helper in `pkg/config/packages_commands.go` — formats user-defined env vars as inline shell prefix using `lo.Map` for key→string mapping and `sort.Strings` for deterministic ordering. Produces: `KEY1="val1" KEY2="val2"`
- [ ] T005 [P] [US1] Rename existing `envVarTmpl` to `formatSecretVar` in `pkg/config/packages_commands.go` — same behavior (secret-resolution template: `NAME="${NAME:-$(cat /run/secrets/NAME 2>/dev/null || true)}"`), update all internal references
- [ ] T006 [P] [US1] Change `formatInstallCommand` signature to `formatInstallCommand(pkgs []string, env map[string]string) string` in `pkg/config/packages_commands.go` — build full command by composing `formatEnvVars(env)` + `formatSecretVar` (for PACKAGES_VERSION and REGISTRY) + `"pm install <pkgs>"`. Update all call sites inside the file
- [ ] T007 [US1] Change `InstallCmd` field type in `PackageEcosystem` struct in `pkg/config/packages_directive.go` to accept `env map[string]string`: `func(workdir, specFile string, specList []string, env map[string]string) string`. Update all ecosystem lambdas to accept the new parameter (they will ignore it for non-os-pm types). Update the os-pm lambda to pass `env` to `formatInstallCommand(specList, env)`. In `GeneratePackagesCommands` in `pkg/config/packages_commands.go`, pass `pkg.Env` to `eco.InstallCmd(...)`
- [ ] T008 [US1] Add table-driven unit tests (`DescribeTable`) for basic env var passthrough in `pkg/config/packages_commands_test.go` — verify that `CUSTOM_VAR="hello-world"` appears as inline prefix before `pm install`, and backward compatibility when `Env` is nil/empty
- [ ] T009 [US1] Add table-driven unit tests (`DescribeTable`) for DOCKER_CONFIG scenario in `pkg/config/packages_commands_test.go` — verify `DOCKER_CONFIG="/run/secrets/docker-config"` appears before `pm install`, and multiple env vars are all present

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Install packages through a corporate proxy (P2)

**Goal**: Users can set `HTTP_PROXY` / `HTTPS_PROXY` in `packages[].env` to route package downloads through a corporate proxy.

**Independent Test**: Configure an intercepted proxy, set `HTTP_PROXY` and `HTTPS_PROXY` env vars in the os-pm section, and verify that package downloads go through the proxy.

### Implementation for User Story 2

- [ ] T010 [US2] Add table-driven unit tests (`DescribeTable`) for proxy env vars in `pkg/config/packages_commands_test.go` — verify `HTTP_PROXY="http://proxy.example.com:8080" HTTPS_PROXY="http://proxy.example.com:8080"` appears before `pm install`

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Customize package manager behavior (P3)

**Goal**: Users can set env vars like `DEBIAN_FRONTEND=noninteractive` to influence package manager behavior.

**Independent Test**: Set `DEBIAN_FRONTEND=noninteractive` in the os-pm env section and verify that apt does not prompt for interactive input during installation.

### Implementation for User Story 3

- [ ] T011 [US3] Add table-driven unit tests (`DescribeTable`) for DEBIAN_FRONTEND env var in `pkg/config/packages_commands_test.go` — verify `DEBIAN_FRONTEND="noninteractive"` appears before `pm install`, and multiple custom env vars are all present

**Checkpoint**: At this point, all user stories should be independently functional

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Edge cases, validation, and quality assurance

- [ ] T012 [P] Add unit tests for empty env map (`env: {}`) in `pkg/config/packages_commands_test.go` — verify backward compatibility (same output as no env), use `DescribeTable`
- [ ] T013 [P] Add unit tests for invalid env var names (POSIX validation) in `pkg/config/raw_packages_directive_test.go` — verify config parse error for names like `1INVALID`, `has=equals`, empty key, special chars; verify valid names like `_MY_VAR`, `HTTP_PROXY`, `DOCKER_CONFIG` pass (use `DescribeTable`)
- [ ] T014 [P] Add unit tests for non-os-pm package types in `pkg/config/packages_commands_test.go` — verify `env` is silently ignored for go-mod, python-pip, etc. (use `DescribeTable`)
- [ ] T015 [P] Add unit tests for empty string values in env in `pkg/config/packages_commands_test.go` — verify `SOME_VAR=""` is passed as-is (use `DescribeTable`)
- [ ] T016 Run `task format`, `task build`, `task lint:golangci-lint golangciPaths="./pkg/config/..."`, and `task test:unit paths="./pkg/config/..."` to verify all changes

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can proceed sequentially in priority order (P1 → P2 → P3)
- **Polish (Final Phase)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational — No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational — No dependencies on US1 (same implementation, just different test scenarios)
- **User Story 3 (P3)**: Can start after Foundational — No dependencies on US1/US2

### Within Each User Story

- Implementation before tests
- Core types before business logic
- Story complete before moving to next priority

### Parallel Opportunities

- All Foundational tasks are sequential (data model changes build on each other)
- T005 (rename `envVarTmpl` → `formatSecretVar`) and T006 (change `formatInstallCommand` signature) modify the same file but are independent — can run in parallel, but sequential recommended to avoid merge conflicts
- T004, T005, T006 are all in `packages_commands.go` — best done sequentially by one developer
- T008 (US1) and T009 (US1 tests) can run in parallel as test additions
- T010 (US2) and T011 (US3) can run in parallel with each other (different test scenarios in same file, but additive)
- All Polish phase tasks marked [P] can run in parallel (different test files or different scenarios)

---

## Parallel Example: User Story 1

```bash
# T004, T005, T006, T007 are implementation — sequential recommended (same file)
# After T007 is done, run tests:
task test:unit paths="./pkg/config/..."
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (no-op)
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- All new env var tests MUST use Ginkgo `DescribeTable` (table-driven) over individual `It` blocks
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence