---
description: "Task list for OCI Attestation Commands feature"
---

# Tasks: OCI Attestation Commands

**Input**: Reverse-engineered from source code in branch `feat/oci/commands-to-manage-oci-artifacts`

**Status**: All tasks are completed (feature already exists)

**Organization**: Tasks are grouped by component, matching the actual implementation.

## Format: `[ID] Description — File(s)`

## Phase 1: Core Library — `pkg/attestation/`

**Purpose**: Shared attestation library providing DSSE, in-toto, key management, and predicate type resolution.

- [x] T001 Implement DSSE envelope wrapping, unwrapping, and verification — `pkg/attestation/dsse.go`
- [x] T002 Implement in-toto Statement v1 wrapping and unwrapping — `pkg/attestation/statement.go`
- [x] T003 Implement predicate type resolution with well-known short names — `pkg/attestation/predicate_types.go`
- [x] T004 Implement signing key loading (PEM: PKCS#8, EC, RSA; HashiCorp Vault) — `pkg/attestation/keys.go`
- [x] T005 Implement verification key loading (PEM public keys) — `pkg/attestation/keys.go`
- [x] T006 Implement `Sign` function — wrap predicate in in-toto statement, sign with DSSE, attach to OCI image — `pkg/attestation/sign.go`
- [x] T007 Implement `Get` function — pull DSSE envelope from OCI image, unwrap, return predicate — `pkg/attestation/get.go`
- [x] T008 Implement `Verify` function — pull DSSE envelope, verify signature, unwrap, return predicate — `pkg/attestation/verify.go`
- [x] T009 Implement `List` function — enumerate attestations from fallback index, report type/digest/signed status — `pkg/attestation/ls.go`

**Checkpoint**: Core library complete — all attestation primitives available.

---

## Phase 2: CLI Commands — `cmd/werf/attest/`

**Purpose**: Cobra command wiring for the four attestation commands.

- [x] T010 Implement `werf attest sign` command — `cmd/werf/attest/sign/sign.go`
- [x] T011 Implement `werf attest get` command — `cmd/werf/attest/get/get.go`
- [x] T012 Implement `werf attest verify` command — `cmd/werf/attest/verify/verify.go`
- [x] T013 Implement `werf attest ls` command — `cmd/werf/attest/ls/ls.go`
- [x] T014 Register `attestCmd()` group in root command tree — `cmd/werf/root/root.go`

**Checkpoint**: All four CLI commands available under `werf attest`.

---

## Phase 3: OCI Artifact Layer — `pkg/oci/artifact/`

**Purpose**: Make existing OCI artifact attachment functions public for reuse by the attestation library.

- [x] T015 Make `Attach` function public (capitalize) — `pkg/oci/artifact/fallback.go`
- [x] T016 Export `PullFallbackIndex` function — `pkg/oci/artifact/fallback.go`

**Checkpoint**: OCI artifact layer exposes necessary API.

---

## Phase 4: SBOM Refactoring — `pkg/sbom/image/`

**Purpose**: Eliminate code duplication by delegating to the new shared attestation library.

- [x] T017 Refactor `pkg/sbom/image/dsse.go` to delegate to `pkg/attestation/` — `pkg/sbom/image/dsse.go`

**Checkpoint**: SBOM subsystem uses shared attestation code.

---

## Phase 5: Unit Tests — `pkg/attestation/*_test.go`

**Purpose**: Unit tests for the core attestation library.

- [x] T018 Write unit tests for DSSE envelope wrap/unwrap (unsigned, signed, wrong payload type, malformed JSON) — `pkg/attestation/dsse_test.go`
- [x] T019 Write unit tests for DSSE signature verification (correct key, wrong key, unsigned, multiple verifiers, malformed JSON) — `pkg/attestation/dsse_test.go`
- [x] T020 Write unit tests for `HasSignatures` — `pkg/attestation/dsse_test.go`
- [x] T021 Write unit tests for in-toto statement wrap/unwrap round-trip — `pkg/attestation/dsse_test.go`
- [x] T022 Write unit tests for predicate type resolution (well-known names, URI passthrough, unknown, empty) — `pkg/attestation/predicate_types_test.go`
- [x] T023 Write integration tests for sign→verify round-trip with correct/wrong keys — `pkg/attestation/integration_test.go`
- [x] T024 Write integration tests for unsigned envelope handling — `pkg/attestation/integration_test.go`
- [x] T025 Write integration tests for malformed input handling — `pkg/attestation/integration_test.go`
- [x] T026 Set up Ginkgo test suite for attestation package — `pkg/attestation/suite_test.go`

**Checkpoint**: All unit and integration tests pass.

---

## Phase 6: E2E Tests — `test/e2e/attest/`

**Purpose**: End-to-end tests exercising the full attestation lifecycle.

- [x] T027 Set up E2E test suite with required tools and environment — `test/e2e/attest/suite_test.go`
- [x] T028 Write common test helpers (key generation, digest extraction, VEX predicate) — `test/e2e/attest/common_test.go`
- [x] T029 Write E2E test: sign → get → verify → ls round-trip with OpenVEX predicate — `test/e2e/attest/lifecycle_test.go`
- [x] T030 Write E2E test: verify fails with wrong key — `test/e2e/attest/lifecycle_test.go`
- [x] T031 Write E2E test: sign fails with missing predicate file — `test/e2e/attest/lifecycle_test.go`
- [x] T032 Write E2E test: sign fails with unknown predicate type — `test/e2e/attest/lifecycle_test.go`
- [x] T033 Write E2E test: get fails when no attestation attached — `test/e2e/attest/lifecycle_test.go`
- [x] T034 Create test fixtures (Dockerfile, werf.yaml) — `test/e2e/attest/_fixtures/simple/`

**Checkpoint**: E2E tests pass.

---

## Phase 7: Test Helpers — `test/pkg/werf/`

**Purpose**: Add attestation test helpers to the shared test package.

- [x] T035 Add `AttestSignOptions` type — `test/pkg/werf/options.go`
- [x] T036 Add `AttestGetOptions` type — `test/pkg/werf/options.go`
- [x] T037 Add `AttestVerifyOptions` type — `test/pkg/werf/options.go`
- [x] T038 Add `AttestLsOptions` type — `test/pkg/werf/options.go`
- [x] T039 Add `AttestSign` method to `Project` — `test/pkg/werf/project.go`
- [x] T040 Add `AttestGet` method to `Project` — `test/pkg/werf/project.go`
- [x] T041 Add `AttestVerify` method to `Project` — `test/pkg/werf/project.go`
- [x] T042 Add `AttestLs` method to `Project` — `test/pkg/werf/project.go`

**Checkpoint**: Test helpers available for attestation commands.

---

## Phase 8: Documentation

**Purpose**: CLI reference documentation and sidebar updates.

- [x] T043 Generate CLI docs for `werf attest` parent command — `docs/_includes/reference/cli/werf_attest.md`
- [x] T044 Generate CLI docs for `werf attest sign` — `docs/_includes/reference/cli/werf_attest_sign.md`
- [x] T045 Generate CLI docs for `werf attest get` — `docs/_includes/reference/cli/werf_attest_get.md`
- [x] T046 Generate CLI docs for `werf attest verify` — `docs/_includes/reference/cli/werf_attest_verify.md`
- [x] T047 Generate CLI docs for `werf attest ls` — `docs/_includes/reference/cli/werf_attest_ls.md`
- [x] T048 Update CLI sidebar (`_cli.yml`) with attestation entries — `docs/_data/sidebars/_cli.yml`
- [x] T049 Update documentation sidebar (`documentation.yml`) — `docs/_data/sidebars/documentation.yml`
- [x] T050 Add English reference pages for all attest commands — `docs/pages_en/reference/cli/`
- [x] T051 Update CLI overview page — `docs/pages_en/reference/cli/overview.md`

**Checkpoint**: All documentation generated and linked.

---

## Gaps Identified

The following gaps were found during reverse-engineering:

1. ⚠️ **`VerifyDSSE` silently continues on base64 decode errors**: When a signature's base64 decoding fails, the loop uses `continue` instead of returning an error or accumulating failures. Malformed signatures are silently skipped, which could mask data corruption.

2. ⚠️ **No `--image` flag in `werf attest ls`**: The `ls` command does not support `--image` for filtering by image name. All attestations for a digest are listed regardless of which image name they were attached under. The underlying `List` function also doesn't filter by image name.

3. ⚠️ **`HasSignatures` returns false on malformed JSON**: If the envelope JSON is malformed, `HasSignatures` returns `false` instead of an error. This is a silent failure that could hide data issues.

4. ⚠️ **No integration tests for `ls` with actual OCI registry**: The `attest ls` command is only tested via E2E tests. There are no unit-level integration tests for the `List` function against a real or mock OCI registry.

5. ⚠️ **No integration tests for `pkg/oci/artifact/fallback.go` changes**: The `Attach` and `PullFallbackIndex` functions were made public but have no direct tests beyond the E2E attestation tests.

## Dependencies & Execution Order

### Phase Dependencies

- **Core Library (Phase 1)**: No dependencies — foundational for all other phases
- **CLI Commands (Phase 2)**: Depends on Phase 1
- **OCI Artifact (Phase 3)**: Independent — only touches existing code
- **SBOM Refactoring (Phase 4)**: Depends on Phase 1
- **Unit Tests (Phase 5)**: Depends on Phase 1
- **E2E Tests (Phase 6)**: Depends on Phase 2, Phase 3
- **Test Helpers (Phase 7)**: Depends on Phase 2
- **Documentation (Phase 8)**: Depends on Phase 2

### Parallel Opportunities

- Phases 1, 3 can be done in parallel (different packages)
- Phases 5, 7 can be done in parallel (different test files)
- All documentation tasks (Phase 8) can be done in parallel