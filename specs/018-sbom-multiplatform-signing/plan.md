# Implementation Plan: Signing of Multi-Platform SBOMs

**Branch**: `feat/sbom/sign-multiplatform-sbom` (from `main`) | **Date**: 2026-08-19 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/018-sbom-multiplatform-signing/spec.md`

## Summary

Join the two shipped SBOM features: per-platform SBOMs (016-sbom-multiplatform-per-platform) are now honest, so the single-platform capability guard from 016-sbom-signing is removed — multi-platform builds with `--sign-key` publish one signed Sigstore Bundle v0.3 per platform manifest, fail-fast on any platform's signing failure. `werf attest verify` on an index reference without `--platform` gains verify-all semantics: every platform's attestation is verified and classified (verified / missing / unsigned-legacy / invalid), succeeding only when all platforms verify. No new stored formats, no index-level artifacts, no checksum composition changes.

Technical approach (grounded in [research.md](research.md)): delete `sbomSigningSupported` + warning branch in `pkg/build/build_phase.go`; add an index-aware verification entry point to `pkg/attestation` reusing `artifact.ListIndexPlatforms` (already skips `unknown/unknown`), `artifact.ErrNotFound`, and `attestation.HasSignatures` for classification; keep `cmd/werf/attest/verify` as thin wiring with a tabwriter result table in verify-all mode.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies** (subset relevant to this feature; NO new dependencies):
- **Attestation/signing**: `sigstore/sigstore` (signature.Verifier), hand-built Sigstore Bundle serializer (`pkg/attestation/bundle.go`, air-gapped constraint from 016)
- **Container registry**: `google/go-containerregistry` (index/manifest resolution via `pkg/oci/artifact`)
- **SBOM**: `CycloneDX/cyclonedx-go`
- **Utilities**: `samber/lo`, `werf/common-go`

**Storage**: OCI container registry — per-platform fallback tags `sha256-<hex>`; artifact formats inherited unchanged (see [data-model.md](data-model.md))

**Testing**: Ginkgo + Gomega; unit tests co-located (`pkg/attestation`, `pkg/build`), e2e in `test/e2e/sbom/` (labels `sbom-signing`, `multiplatform`, `simple` — runs in the `e2e_simple` CI job; cosign binary optional)

**Target Platform**: Linux (amd64/arm64); macOS builds a non-CGO binary — e2e requires Linux (pre-configured per constitution)

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: No new goals — verify-all adds N registry round-trips for an N-platform index (N ≤ handful), sequential is fine

**Constraints**: Byte-identity of all pre-existing artifacts and checksums (spec FR-008/FR-009, SC-004); no content sniffing (016 FR-006); `attest` command tree stays hidden (spec 008) — no `task doc:gen` needed unless flag help text changes (it does: `--platform` help on `verify` mentions being required for index — must be updated, so `task doc:gen` IS required)

**Scale/Scope**: 2 production packages touched (`pkg/build`, `pkg/attestation`) + 1 cmd file; ~4 e2e scenarios; no migrations

## Constitution Check

*GATE: evaluated against constitution v1.4.0 — PASS (pre-Phase-0 and re-checked post-Phase-1).*

| Principle | Compliance |
|---|---|
| I. Simplicity Over Abstraction | Guard function deleted, not abstracted; verify-all is one exported function returning a slice of plain result structs; no interfaces/generics added |
| II. Go Idiomatic Code | New public function takes `ctx` first; errors wrapped with action context; guard clauses in classification; no named returns |
| III. Minimal Public Surface | One new exported entry point in `pkg/attestation` + result type; status enum as type-prefixed string constants (no `iota`) |
| IV. Test-Before-Merge | Ginkgo/Gomega only; unit tests co-located; DescribeTable for classification matrix; e2e re-run after every change; `--` separator rule respected in all commands |
| V. Conventional Commits | Branch `feat/sbom/sign-multiplatform-sbom`; commits `feat(sbom, attest): ...` |
| Code Boundaries | Business logic in `pkg/attestation`; `cmd/werf/attest/verify` stays thin wiring |
| Dependency Rules | Zero new external dependencies |
| Build & Quality Gates | `task format` → `task build` → `task lint` → `task test:unit`; `task doc:gen` after `--platform` help-text change; e2e via `task test:e2e` |

**Environment note**: `task test:setup:environment` has already been executed and the e2e/integration test environment is pre-configured. Do not skip e2e tests citing environment setup during implementation.

## Project Structure

### Documentation (this feature)

```text
specs/018-sbom-multiplatform-signing/
├── plan.md              # This file
├── spec.md              # Feature specification (clarified 2026-08-19)
├── research.md          # Phase 0 — R1–R7, all decisions grounded in main @ e2a9f3546
├── data-model.md        # Phase 1 — inherited invariants, removed guard, verification result type
├── quickstart.md        # Phase 1 — validation guide (gates, unit, e2e, manual cosign)
├── contracts/
│   ├── build-signing.md       # werf build behavior matrix + artifact contract
│   └── attest-verify-cli.md   # attest verify resolution matrix + verify-all output
├── checklists/requirements.md # Spec quality checklist (16/16)
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
pkg/build/
└── build_phase.go            # REMOVE sbomSigningSupported (line 408) + warning branch in
                              # convergeImageSbom (lines 316–323); signer passed whenever Enabled

pkg/attestation/
├── verify.go                 # ADD index-aware verify-all entry point (per-platform loop,
│                             # classification per research R3, aggregate error)
├── verify_index_test.go      # NEW co-located unit tests (DescribeTable: 4 statuses × formats)
└── (get.go, dsse.go, ls.go)  # REUSED unchanged: pullAttestationContent, HasSignatures, VerifyDSSE

pkg/oci/artifact/
└── platform.go               # REUSED unchanged: ListIndexPlatforms (skips unknown/unknown),
                              # ResolvePlatformDigest (still backs --platform and get commands)

cmd/werf/attest/verify/
└── verify.go                 # WIRE: branch on --platform absence + index; tabwriter table
                              # (style of cmd/werf/attest/ls); update --platform flag help text

test/e2e/sbom/
├── signing_test.go           # EXTEND or sibling file: signed multi-platform scenario
│                             # Label("e2e","sbom","sbom-signing","multiplatform","simple")
├── multiplatform_test.go     # REUSED helpers/fixtures; strict get-command assertions unchanged
└── (helpers)                 # buildTrustedBuilderBase, generateSigningKeyPairWithCert reused

docs/_includes/reference/cli/ # regenerated via task doc:gen (verify --platform help text)
```

**Structure Decision**: Monolith CLI — all business logic lands in existing `pkg/build` and `pkg/attestation` packages; `cmd/werf/attest/verify` remains thin wiring. No new packages, no new commands.

## Complexity Tracking

No constitution violations — table intentionally empty.
