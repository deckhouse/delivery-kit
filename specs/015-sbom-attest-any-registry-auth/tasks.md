# Tasks: Default Registry Auth for OCI Artifact Attestation Retrieval

**Input**: Design documents from `/specs/015-sbom-attest-any-registry-auth/`

**Prerequisites**: spec.md, plan.md

## Phase 1: Bug Fix — Consistent authentication in `GetAttachedContentAny`

**Purpose**: Ensure `OCIStore.GetAttachedContentAny` uses the same authentication fallback as all other methods

- [x] T001 [FR-001] Change `GetAttachedContentAny` to use `s.remoteOptions(ctx)` instead of `s.opts` in `pkg/oci/artifact/store.go`

## Phase 2: Tests — Integration test for default registry auth

**Purpose**: Verify the fix works with a registry that requires authentication

- [x] T002 [FR-001][SC-001] Add `Describe("Default registry authentication (integration)", ...)` test to `pkg/oci/artifact/attach_integration_test.go` with a basic-auth test registry
- [x] T003 [FR-001][SC-001] Implement test: create OCIStore without explicit auth options, attach an artifact with explicit auth, then retrieve it via `GetAttachedContentAny` using default `docker_registry` auth
- [x] T004 [FR-002] Verify that `GetAttachedContentAny` still works when explicit auth options are provided (existing test coverage preserved)

## Dependencies

- T001 must complete before T002–T004

## Implementation Strategy

This is a single-task fix (T001) with a companion test suite (T002–T004). The production change is one line and follows the established pattern used by all other OCIStore methods.

## Identified Gaps

- No unit test for the `remoteOptions` fallback logic itself — the fix relies on the integration test to verify the behavior end-to-end