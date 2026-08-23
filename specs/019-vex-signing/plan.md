# Implementation Plan: VEX Signing at Build Time with Cosign Compatibility

**Branch**: `feat/sbom/sign-vex` (from `main`) | **Date**: 2026-08-21 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/019-vex-signing/spec.md`

## Summary

Sign VEX documents at build time with the existing `--sign-key`/`--sign-cert` signer (gate: key presence, same as SBOM): the signed artifact is a Sigstore Bundle v0.3 with unversioned predicate `https://openvex.dev/ns`, attached where VEX lives today — the image manifest digest (single-platform) or the image index digest (multi-platform), in-toto subject = that digest. To make signed (and unsigned) SBOM and VEX artifacts coexist, the fallback-index slot key gains the cosign-convention predicate dimension (`dev.sigstore.bundle.predicateType` annotation), fixing the latent mutual-eviction defect; reads become predicate-aware with content-verified legacy fallback. The VEX publish checksum gains a format version and the signer fingerprint. `attest verify/get --type openvex` operate on the index digest without `--platform` and classify unsigned artifacts distinctly.

Technical approach grounded in [research.md](research.md) (R1–R8); artifact shapes in [data-model.md](data-model.md); external contracts in [contracts/](contracts/).

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies** (subset relevant to this feature; NO new dependencies):
- **Attestation/signing**: `sigstore/sigstore` (signature.Signer/Verifier), `deckhouse/delivery-kit-sdk/pkg/signver` (key loading), hand-built Sigstore Bundle serializer (`pkg/attestation/bundle.go`, air-gapped constraint from 016)
- **Container registry**: `google/go-containerregistry` (fallback index, manifest resolution via `pkg/oci/artifact`)
- **Utilities**: `samber/lo`, `werf/common-go`

**Storage**: OCI container registry — fallback tags `sha256-<hex>`; slot identity extended with the predicate-type annotation (see [contracts/artifact-slot-discrimination.md](contracts/artifact-slot-discrimination.md))

**Testing**: Ginkgo + Gomega; unit tests co-located (`pkg/oci/artifact`, `pkg/attestation`, `pkg/build`, `pkg/vex`), e2e in `test/e2e/vex/` (label `VEX`) and `test/e2e/sbom/` (label `sbom-signing`)

**Target Platform**: Linux (amd64/arm64); macOS builds a non-CGO binary — e2e requires Linux (pre-configured per constitution)

**Project Type**: CLI tool (Go binary via `cmd/werf/main.go`)

**Performance Goals**: No new goals — one extra sign+wrap per image with a `vex` field; legacy-candidate content verification adds at most one small blob fetch per read of a pre-feature artifact

**Constraints**: Unsigned VEX payload byte-form identical to 013 (annotation on descriptor is additive); SBOM payloads and checksum composition untouched; no content sniffing on the primary path (annotation first, content verification only for legacy annotation-less entries); `attest` command tree stays hidden; `--platform` help text of `attest verify`/`get` changes → `task doc:gen` required

**Scale/Scope**: 4 production packages touched (`pkg/oci/artifact`, `pkg/attestation`, `pkg/build`, `pkg/vex/image`) + 2 cmd files; ~5 e2e scenarios; no migrations

## Constitution Check

*GATE: evaluated against constitution v1.5.6 — PASS (pre-Phase-0 and re-checked post-Phase-1).*

| Principle | Compliance |
|---|---|
| I. Simplicity Over Abstraction | `VexSigningOptions` is a copy of the SBOM options struct (deliberate duplication over abstraction); slot-key change extends existing functions with one parameter, no new interfaces/generics |
| II. Go Idiomatic Code | New/changed public functions take `ctx` first; errors wrapped with action context; guard clauses; no named returns |
| III. Minimal Public Surface | New exported surface: `signing.VexSigningOptions` + constructor, predicate-aware store lookup, openvex alias handling in `pkg/attestation`; everything else stays package-private |
| IV. Test-Before-Merge | Ginkgo/Gomega only; DescribeTable for slot-key matrix and alias resolution; mocks via `task mock:generate` if needed |
| V. Conventional Commits | Branch `feat/sbom/sign-vex`; commits `feat(sbom, vex): ...` / `feat(vex, attest): ...` |
| Code Boundaries | Business logic in `pkg/`; `cmd/werf/attest/*` and `cmd/werf/common` stay thin wiring |
| Dependency Rules | Zero new external dependencies |
| Build & Quality Gates | `task format` → `task build` → `task lint` → `task test:unit` → scoped `task test:e2e` → `task test:integration`; `task doc:gen` after help-text change |

**Environment note**: `task test:setup:environment` has already been executed and the e2e/integration test environment is pre-configured. Do not skip e2e tests citing environment setup during implementation.

**Lint**:
- **Prerequisites (once per session)**: run `task deps:install:golangci-lint` before the first lint run.
- **Usage**: then run `task lint` (scoped iteration: `task lint:golangci-lint golangciPaths="./pkg/..."`).

**Unit tests**:
- **Usage**: scoped example `task test:unit paths="./pkg/oci/artifact/..."`.
- **Focused**: `task test:unit paths="./pkg/attestation/..." -- -focus=MyTest -v`.

**E2E tests**:
- **Prerequisites (once per session)**: the environment is already prepared. Do not run or check `task test:setup:environment` or skip tests for setup reasons.
- **Usage**: always run `task test:e2e` scoped with both `paths` and `labelFilter`.
  - Scoped: `task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"`.
  - Focused: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom-signing" -- -focus=MyTest -v`.

## Project Structure

### Documentation (this feature)

```text
specs/019-vex-signing/
├── plan.md              # This file
├── spec.md              # Feature specification (Customer Decisions 1–7 recorded)
├── research.md          # Phase 0 — R1–R8, grounded in main + industry research (cosign/vexctl/scout)
├── data-model.md        # Phase 1 — artifact shapes, slot identity, checksum transitions
├── quickstart.md        # Phase 1 — validation guide (gates, unit, e2e, manual cosign)
├── contracts/
│   ├── build-vex-signing.md            # werf build behavior matrix + artifact contract
│   ├── attest-openvex-cli.md           # attest verify/get openvex resolution + classification
│   └── artifact-slot-discrimination.md # fallback-index slot key, write/read rules
├── checklists/requirements.md          # Spec quality checklist (16/16)
└── tasks.md             # Phase 2 output (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
pkg/oci/artifact/
├── fallback.go               # CHANGE: isArtifactKey/updateFallbackIndex/isAttached/matchDescriptors
│                             # gain the predicate dimension; legacy ("" predicate) candidate rules
├── store.go                  # CHANGE: Attach/AttachSuperseding carry predicate annotation
│                             # (dev.sigstore.bundle.predicateType) into artifactAnnotations;
│                             # predicate-aware GetAttached* lookups
└── *_test.go                 # NEW/EXTEND: DescribeTable slot-key matrix (SBOM×VEX×signed×legacy)

pkg/attestation/
├── predicate_types.go        # CHANGE: openvex alias set {ns, ns/v0.2.0}; matching helper
├── get.go, verify.go         # CHANGE: predicate-aware artifact selection (alias-set match,
│                             # legacy content-verified fallback); unsigned classification error
└── *_test.go                 # EXTEND: alias resolution, classification

pkg/build/signing/
└── vex_signing.go            # NEW: VexSigningOptions (mirror of sbom_signing.go)

pkg/build/
├── build_phase.go            # CHANGE: convergeImageVex extracts signer/identity from
│                             # VexSigningOptions and passes to vexStep.Converge
├── vex_step.go               # CHANGE: checksum = stable-hash{content, digest, formatVersion="2",
│                             # fingerprint}; publish-needed check predicate-aware, dual-format
├── conveyor.go               # CHANGE: ConveyorOptions.VexSigningOptions
└── sbom_step.go / sbom image # CHANGE (minimal): pass predicate annotation on SBOM publishes

pkg/vex/image/
└── image.go                  # CHANGE: PushVEX accepts signer; signed path = HasSignatures check →
                              # WrapInBundle → AttachSuperseding(Bundle, superseded DSSE-vex);
                              # unsigned path byte-identical payload + annotation

cmd/werf/common/
├── signature.go              # CHANGE: getVexSigningOptions (gate: SignKey != "")
└── conveyor_options.go       # CHANGE: plumb VexSigningOptions into Build/Conveyor options

cmd/werf/attest/{verify,get}/ # CHANGE: openvex → index digest used as-is; --platform+openvex+index
                              # usage error; --platform help text updated → task doc:gen

test/e2e/vex/                 # EXTEND: signing scenarios (US1, US3–US5), Label("e2e","VEX","simple")
test/e2e/sbom/                # NEW scenario: SBOM+VEX coexistence (US2), Label("sbom-signing")
docs/_includes/reference/cli/ # regenerated via task doc:gen
```

**Structure Decision**: Monolith CLI — all business logic in existing `pkg/` packages; `cmd/werf/*` stays thin wiring. No new packages except one new file in `pkg/build/signing/`. No new commands.

## Cross-branch note

The unmerged 018 branch (`feat/sbom/sign-multiplatform-sbom`) touches `pkg/build/build_phase.go` (SBOM guard removal) and `cmd/werf/attest/verify/verify.go` (verify-all). Overlap with this feature is small and semantically independent: VEX changes in `build_phase.go` live in `convergeImageVex` (different function), and the verify change here is scoped to the openvex predicate branch. Merge order does not matter (spec Assumptions).

## Complexity Tracking

No constitution violations — table intentionally empty.
