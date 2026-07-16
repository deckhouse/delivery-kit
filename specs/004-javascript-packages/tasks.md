---

description: "Task list for JavaScript package ecosystem support in werf packages directive"
---

# Tasks: JavaScript Package Ecosystems

**Input**: Design documents from `specs/004-javascript-packages/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: The spec does not explicitly request TDD-style tests-first. Test tasks are included as verification tasks after implementation, following the existing patterns from Python and Rust implementations.

**Organization**: Tasks are grouped by user story. All three JavaScript types share the same foundational code path (constants + registry entries), so the unit tests for config parsing, SBOM catalogers, and command generation cover all three types together. Each type gets its own e2e test as an independently verifiable slice.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4)
- Include exact file paths in descriptions

## Path Conventions

- **Business logic**: `pkg/config/`
- **Unit tests**: co-located with source files as `*_test.go`
- **E2E tests**: `test/e2e/sbom/`
- **E2E fixtures**: `test/e2e/sbom/_fixtures/inject/`
- **Test helpers**: `test/pkg/sbom/`
- **Docs config**: `docs/_data/werf_yaml.yml`
- **Docs pages**: `docs/pages_{en,ru}/usage/build/stapel/instructions.md`

## Build & Test Commands

- **Build**: `task build` (produces `./bin/werf`)
- **Unit tests**: `task test:unit -- -run <pattern> ./pkg/<path>/...`
- **E2E tests**: `task test:e2e -- labelFilter="<label>" ./test/e2e/...`
- **Linting**: `task lint:golangci-lint -- golangciPaths="./pkg/..."`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: No setup needed — the project already exists and the `ecosystems` map, `FileBasedSpec`, `PackageEcosystem`, and `buildResolvers` infrastructure are all already in place from the Python and Rust implementations.

No tasks for this phase.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core implementation that MUST be complete before any user story can be verified

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T001 Add three `PackagesDirectiveType` constants (`PackagesDirectiveTypeJavaScriptNpm`, `PackagesDirectiveTypeJavaScriptYarn`, `PackagesDirectiveTypeJavaScriptPnpm`) and three `PackageEcosystem` entries in the `ecosystems` map in `pkg/config/packages_directive.go`
- [X] T002 [P] Update `docs/_data/werf_yaml.yml` type descriptions to include `javascript-npm`, `javascript-yarn`, `javascript-pnpm` in the `type` field description, and update `workdir`, `spec`, `lock` descriptions to list new defaults
- [X] T003 [P] Add JavaScript package ecosystem sections to EN docs in `docs/pages_en/usage/build/stapel/instructions.md` following the same pattern as the existing Rust Cargo section
- [X] T004 [P] Add JavaScript package ecosystem sections to RU docs in `docs/pages_ru/usage/build/stapel/instructions.md` following the same pattern as the existing Rust Cargo section

**Checkpoint**: Foundation ready — constants, registry entries, and documentation are in place. User story verification can now begin.

---

## Phase 3: User Story 1 — npm Support (Priority: P1) 🎯 MVP

**Goal**: A user can declare `type: javascript-npm` in the `packages` directive with `workdir: /app`, and werf runs `npm ci`, generates an SBOM with `javascript-lock-cataloger` and `javascript-package-cataloger`, and filters components by the declared source paths.

**Independent Test**: `task test:unit -- -run "javascript-npm" ./pkg/config/...` passes for npm config parsing; `task test:e2e -- labelFilter="npm" ./test/e2e/...` passes for npm e2e.

### Verification for User Story 1

- [X] T005 [P] [US1] Add config parsing unit tests for `javascript-npm` with only workdir (defaults spec and lock), with explicit spec/lock overrides, and missing workdir (error case) in `pkg/config/packages_directive_javascript_test.go`. Also test that unknown type `javascript-bower` is rejected.
- [X] T006 [P] [US1] Extend SBOM cataloger tests in `pkg/sbom/managedinput/managedinput_test.go` to verify `ToCatalogers` returns correct `javascript-lock-cataloger` entries for `javascript-npm` with spec and lock source paths, and that `FilterBOMBySourcePaths` correctly filters components for npm entries.
- [X] T007 [US1] Extend command generation tests in `pkg/build/stage/packages_test.go` to verify `GeneratePackagesCommands` produces `cd "<workdir>" && npm ci` for `javascript-npm` entries.
- [X] T008 [US1] Create npm e2e test in `test/e2e/sbom/npm_test.go` with fixture in `test/e2e/sbom/_fixtures/inject/npm_simple/` (package.json + package-lock.json with expected dependency). Follow the `cargo_test.go` pattern: build image, get SBOM, verify `lodash@4.17.21` is present.

**Checkpoint**: At this point, npm support should be fully functional and testable independently.

---

## Phase 4: User Story 2 — Yarn Support (Priority: P1)

**Goal**: A user can declare `type: javascript-yarn` in the `packages` directive with `workdir: /app`, and werf runs `yarn install --frozen-lockfile`, generates an SBOM with `javascript-lock-cataloger` and `javascript-package-cataloger`, and filters components by the declared source paths.

**Independent Test**: `task test:unit -- -run "javascript-yarn" ./pkg/config/...` passes for yarn config parsing; `task test:e2e -- labelFilter="yarn" ./test/e2e/...` passes for yarn e2e.

### Verification for User Story 2

- [X] T009 [US2] Create yarn e2e test in `test/e2e/sbom/yarn_test.go` with fixture in `test/e2e/sbom/_fixtures/inject/yarn_simple/` (package.json + yarn.lock with expected dependency). Follow the same pattern as `cargo_test.go`: build image, get SBOM, verify `lodash@4.17.21` is present.

**Checkpoint**: npm and yarn support should both be independently functional.

---

## Phase 5: User Story 3 — pnpm Support (Priority: P1)

**Goal**: A user can declare `type: javascript-pnpm` in the `packages` directive with `workdir: /app`, and werf runs `pnpm install --frozen-lockfile`, generates an SBOM with `javascript-lock-cataloger` and `javascript-package-cataloger`, and filters components by the declared source paths.

**Independent Test**: `task test:unit -- -run "javascript-pnpm" ./pkg/config/...` passes for pnpm config parsing; `task test:e2e -- labelFilter="pnpm" ./test/e2e/...` passes for pnpm e2e.

### Verification for User Story 3

- [X] T010 [US3] Create pnpm e2e test in `test/e2e/sbom/pnpm_test.go` with fixture in `test/e2e/sbom/_fixtures/inject/pnpm_simple/` (package.json + pnpm-lock.yaml with expected dependency). Follow the same pattern as `cargo_test.go`: build image, get SBOM, verify `lodash@4.17.21` is present.

**Checkpoint**: All three JavaScript types should now be independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Mixed configurations, integration tests, and final validation

- [X] T011 [P] Add mixed config and monorepo unit tests in `pkg/config/packages_directive_javascript_test.go`: verify `go-mod` + `javascript-npm` + `os-pm` combined config generates all expected commands and catalogers; verify multiple `javascript-*` entries with different types and workdirs produce correct separate commands and cataloger entries.
- [X] T012 Run full test suite: `task test:unit` passes, `task lint:golangci-lint` passes, and `task test:e2e -- labelFilter="javascript"` passes.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — nothing needed
- **Foundational (Phase 2)**: No dependencies — can start immediately — BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
  - US1 (npm) is the MVP — provides the full implementation path for unit tests and e2e tests
  - US2 (yarn) and US3 (pnpm) depend on the same foundational code — their e2e tests are independent
- **Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (npm)**: Can start after Phase 2 — includes unit tests for all JS types + npm e2e
- **User Story 2 (yarn)**: Can start after Phase 2 — only e2e test needed (unit tests already in US1)
- **User Story 3 (pnpm)**: Can start after Phase 2 — only e2e test needed (unit tests already in US1)
- **US4 (mixed/monorepo)**: Can start after US1 — extends unit tests

### Parallel Opportunities

- **Phase 2**: T002 (docs_yaml), T003 (EN docs), T004 (RU docs) can run in parallel
- **Phase 3**: T005 (config tests), T006 (SBOM tests) can run in parallel
- **Phases 3-5**: Once Phase 2 completes, all three e2e tests (T008 npm, T009 yarn, T010 pnpm) can be written in parallel
- **Phase 6**: T011 (mixed/monorepo tests) can run in parallel with e2e test work

### Within Each User Story

- Config parsing tests → SBOM tests → Command generation tests → e2e tests
- E2e tests for each type are independent of each other

---

## Parallel Example: User Story 1 (npm)

```bash
# Launch config parsing tests and SBOM tests together:
Task: "task test:unit -- -run TestConfig.*javascript ./pkg/config/..."
Task: "task test:unit -- -run TestToCatalogers.*javascript ./pkg/sbom/managedinput/..."

# Launch e2e test:
Task: "task test:e2e -- labelFilter=\"npm\" ./test/e2e/..."
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 2: Foundational (constants + registry + docs)
2. Complete Phase 3: User Story 1 (npm: unit tests + e2e)
3. **STOP and VALIDATE**: Test npm independently
4. Deploy/demo if ready

### Incremental Delivery

1. Complete Phase 2 → Foundation ready
2. Add npm (US1) → Test independently → Deploy/Demo (MVP!)
3. Add yarn (US2) → Test independently → Deploy/Demo
4. Add pnpm (US3) → Test independently → Deploy/Demo
5. Add mixed/monorepo tests (US4) → Polish

### Parallel Team Strategy

With multiple developers:

1. Team completes Phase 2 together
2. Once Phase 2 is done:
   - Developer A: US1 (npm — unit tests + e2e)
   - Developer B: US2 (yarn — e2e only)
   - Developer C: US3 (pnpm — e2e only)
3. All three e2e tests can be written in parallel since they share the same pattern

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- All three JavaScript types share the same Syft cataloger (`javascript-lock-cataloger`) — no Syft configuration changes needed
- The `javascript-package-cataloger` for `package.json` is automatically applied by the `buildResolvers()` function — no additional code needed