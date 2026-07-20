# Implementation Plan: OCI Attestation Commands

**Branch**: `feat/oci/commands-to-manage-oci-artifacts` | **Date**: 2026-07-15 | **Spec**: `specs/002-oci-attestation-commands/spec.md`

**Input**: Feature specification reverse-engineered from source code changes in branch `feat/oci/commands-to-manage-oci-artifacts`

## Summary

Add four new CLI commands under `werf attest` (`sign`, `get`, `verify`, `ls`) for managing in-toto attestations on OCI images. The core library `pkg/attestation/` provides DSSE envelope signing/verification, in-toto statement wrapping, predicate type resolution, and key loading. Attestations are stored as OCI artifacts using the pre-existing fallback index mechanism in `pkg/oci/artifact/`. The existing `pkg/sbom/image/dsse.go` is refactored to delegate to the new shared library.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **Kubernetes deployment**: `werf/nelm`, `werf/kubedog`, Helm chart primitives
- **Kubernetes client**: `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`
- **Container registry**: `google/go-containerregistry`, `aws/aws-sdk-go-v2` (ECR)
- **Attestation**: `secure-systems-lab/go-securesystemslib` (DSSE), `sigstore/sigstore` (crypto signing), `in-toto/in-toto-golang` (in-toto statement), `deckhouse/delivery-kit-sdk` (HashiCorp Vault signer)
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`, `docker/docker` (API client)

**New Dependencies**:
- `github.com/secure-systems-lab/go-securesystemslib` — DSSE envelope types
- `github.com/sigstore/sigstore` — Signature and verification primitives
- `github.com/in-toto/in-toto-golang` — In-toto statement types
- `github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault` — HashiCorp Vault signer

**Storage**: OCI container registry (Docker v2, ECR) — attestations stored as OCI artifacts via fallback index tags

**Testing**: Ginkgo + Gomega for unit tests (co-located), integration tests, and e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah; Kubernetes clusters

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: Attestation signing/verification should complete in < 5s for typical predicate sizes; CAS retry mechanism handles concurrent writes without data loss

**Constraints**: CLI must be self-contained; no daemon dependency; OCI-compatible registry interaction; attestations must be interoperable with in-toto and DSSE standards

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

All gates passed. The implementation follows existing patterns:
- CLI commands are thin wrappers (`cmd/werf/attest/`) delegating to `pkg/attestation/`
- Business logic is in `pkg/` with no dependency on `cmd/`
- Tests use Ginkgo + Gomega, co-located with source files
- All public functions accept `context.Context` as first parameter
- Errors are wrapped with context
- No new interfaces or abstractions beyond what's needed
- No new comments added beyond what's genuinely non-obvious

## Project Structure

### Documentation (this feature)

```text
specs/002-oci-attestation-commands/
├── spec.md              # This file (reverse-engineered)
├── plan.md              # This file
└── tasks.md             # Task list (all completed)
```

### Source Code (repository root)

```text
cmd/werf/attest/                  # NEW — CLI command group
├── sign/
│   ├── sign.go                   # werf attest sign command
│   └── sign_docs.go              # CLI help text
├── get/
│   ├── get.go                    # werf attest get command
│   └── get_docs.go               # CLI help text
├── verify/
│   ├── verify.go                 # werf attest verify command
│   └── verify_docs.go            # CLI help text
└── ls/
    ├── ls.go                     # werf attest ls command
    └── ls_docs.go                # CLI help text

cmd/werf/root/root.go             # MODIFIED — registered attestCmd() group

pkg/attestation/                  # NEW — core attestation library (7 files)
├── dsse.go                       # DSSE envelope wrap/unwrap/verify
├── dsse_test.go                  # Unit tests for DSSE operations
├── sign.go                       # Sign attestation and attach to OCI image
├── get.go                        # Get attestation from OCI image
├── verify.go                     # Verify signed attestation
├── ls.go                         # List attestations on an image
├── keys.go                       # Signing/verification key loading
├── statement.go                  # In-toto statement wrap/unwrap
├── predicate_types.go            # Predicate type resolution
├── predicate_types_test.go       # Unit tests for predicate types
├── integration_test.go           # Integration tests (sign→verify round-trip)
└── suite_test.go                 # Ginkgo test suite

pkg/sbom/image/dsse.go           # MODIFIED — refactored to use pkg/attestation/
pkg/oci/artifact/fallback.go     # MODIFIED — Attach, PullFallbackIndex made public

test/e2e/attest/                  # NEW — e2e tests
├── _fixtures/simple/
│   ├── Dockerfile
│   └── werf.yaml
├── common_test.go                # Common test setup
├── lifecycle_test.go             # End-to-end lifecycle tests
└── suite_test.go                 # E2E test suite

test/pkg/werf/options.go          # MODIFIED — added Attest*Options
test/pkg/werf/project.go          # MODIFIED — added AttestSign/Get/Verify/Ls methods

docs/                             # MODIFIED — CLI reference docs, sidebars, pages
└── ...
```

## Complexity Tracking

No constitution violations. Simpler approach would be impossible given the need to comply with DSSE and in-toto standards.

| Component | Complexity | Rationale |
|-----------|-----------|-----------|
| DSSE envelope | Low | Direct JSON marshal/unmarshal with base64 payload |
| In-toto statement | Low | Simple JSON structure with subject/name/digest |
| Key loading | Medium | Multiple PEM formats, HashiCorp Vault integration |
| OCI artifact attachment | Medium | CAS retry, fallback index management, concurrent write detection |
| Signature verification | Medium | Multiple verifiers, multiple signatures, any-match semantics |
| CLI commands | Low | Standard cobra command wiring, reuses common CLI setup patterns |
| Predicate type resolution | Low | Simple map lookup with URI passthrough |