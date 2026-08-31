# Research: SBOM Checksum Completeness

**Feature**: specs/019-sbom-checksum-completeness | **Date**: 2026-08-24

## R1: Current checksum computation and its gaps

**Decision**: Extend `sbomStep.calculateStableChecksum` (`pkg/build/sbom_step.go:180`) to include the GOST configuration; replace the ambiguous `strings.Join(parts, "-")` + single-hash scheme with keyed parts fed to `util.Sha256Hash`. Neither the stapel-scratch flag nor the os-pm flag is added: `from: scratch` changes alter the digest of every stage, and the os-pm package list feeds the Packages stage digest through the generated install command (`pkg/config/packages_directive.go` ecosystems registry → `Shell.Packages` → `PackagesChecksum` → `pkg/build/stage/packages.go`), with the stage itself appearing/disappearing with the directive — both are covered by the parent digest half of the cache key.

**Rationale**: The checksum is compared against the `image.WerfChecksumAnnotation` on the attached artifact (`ConvergeWithMerge`, sbom_step.go:82). The cache key is the pair (parent stage digest, checksum). The parent digest covers image filesystem content; the checksum must cover every other generation input. Verified current inputs:

- `sbomArtifactFormatVersion` ("2") — covers generator logic changes.
- `scanOpts.Checksum()` (`pkg/sbom/scanner/scan_options.go:11`) — scanner image (`anchore/syft:v1.45.1`), and per-command (`scan_command.go:85`): scanner type, source type, output standard, catalogers with source paths. `SourcePath` is intentionally excluded (it is the stage name, varies per build without affecting content).
- `mergeOpts.Checksum()` (`pkg/sbom/cyclonedxutil/merge.go:25`) — `StableBOMChecksum` of base BOM and import BOMs (excludes SerialNumber, Version, Signature, Metadata.Timestamp).
- `signerIdentity`, `targetPlatform`.

Missing inputs confirmed by reading `ConvergeWithMerge` and `convergePlatformImageSbom` (`pkg/build/build_phase.go:440`):

- `osPmEnabled` (from `HasOSPMPackages()`) and `isStapelScratch` select generation paths (sbom_step.go:94,126) but are both covered by the parent digest: any os-pm directive change alters the generated install command and thus the Packages stage digest (specs/018 affects only file-based types whose commands contain paths, not the inline os-pm list), and a base image change alters every stage digest.
- `mergeOpts.Gost` — applied via `gost.Upsert(resultBOM, ...)` (sbom_step.go:159). Reflected in the checksum only through `prepareGostComponents` side effects on base/import BOMs *before* checksum computation; with empty `mergeOpts` the config is invisible to the checksum.

**Alternatives considered**:
- Including GOST config inside `MergeOpts.Checksum()` — rejected: GOST is post-processing config, not a merge input; would double-count the input already leaked via upserted base/import BOMs and conflate concerns.
- Relying on stage-digest invalidation for the `packages` directive (specs/018) — rejected as the sole fix: the SBOM checksum layer must be self-sufficient; stage invalidation is a separate defense.

## R2: GOST config serialization for the checksum

**Decision**: Serialize `gost.Config` (`pkg/sbom/cyclonedxutil/gost/config.go`) as explicit key/value parts, e.g. `"gost_attack_surface", cfg.AttackSurface.String(), "gost_security_function", cfg.SecurityFunction.String()`. Undefined values serialize as the empty string, which is the "GOST not configured" state.

**Rationale**: `Config` is two string-typed enum fields (`GostValue`: `yes`/`no`/`indirect`/``). Keyed serialization is deterministic, stable across field reordering, and matches the existing `ScanCommand.Checksum()` style. JSON marshaling would also work but adds fragility (field renames change the checksum silently).

**Alternatives considered**: JSON-marshal the struct — rejected (tag/field renames silently alter checksums; keyed pairs make the contract explicit).

## R3: Injective part encoding

**Decision**: Pass all parts as separate arguments to `util.Sha256Hash(parts...)` with fixed positions and key labels for the new parts; drop the intermediate `strings.Join(parts, "-")`.

**Rationale**: `util.Sha256Hash` (werf/common-go `pkg/util/hashsum.go`) joins args with `":::"`. Current code joins with `"-"` first, so empty parts (`mergeOpts.Checksum()` when no base/imports, empty `signerIdentity`) collapse into ambiguous `--` sequences, and the conditional `targetPlatform` append shifts part positions. Fixing: always append every part (no conditional omission), label parts with keys (`"gost_attack_surface", value`), and let each part occupy a fixed argument slot. Existing parts are hex digests, version literals, platform strings, and key fingerprints — none can contain `":::"`, so joint-level collisions are not practically reachable; positional fixedness removes the shifting ambiguity.

**Alternatives considered**: Length-prefixed encoding or hashing each part individually — rejected as over-engineering; fixed arity + keyed parts + `":::"` separator is sufficient and matches repo conventions.

## R4: Rollout / invalidation wave

**Decision**: Ship all checksum changes in one PR. Do not bump `sbomArtifactFormatVersion`: the checksum value changes anyway for every image because the part layout changes, which forces exactly one regeneration wave.

**Rationale**: The annotation comparison is equality-based; any change to the computation invalidates all cached SBOMs once. A version bump would be redundant (the layout change already guarantees a new checksum) but harmless; keeping the version at "2" reserves bumps for generator-logic changes per its documented purpose. Either way the wave is single because everything lands together (FR-007).

## R5: Out-of-scope confirmations

**Decision**: gomod patcher inputs, externalref enrichment, the scratch-base mode, and the os-pm packages directive stay out of the checksum; document this at the computation site (FR-006).

**Rationale**:
- gomod patcher reads `go.mod`/`go.sum` at the HEAD commit plus `imageContext`; changes to those inputs alter the build context and therefore the stage digest, which is the cache key's other half — covered transitively. Patcher logic changes are covered by `sbomArtifactFormatVersion`.
- externalref enrichment depends on external package indexes — a non-deterministic input that cannot be meaningfully pinned in a checksum.

## R6: Test seams

**Decision**: Unit-test `calculateStableChecksum` via a table (Ginkgo `DescribeTable`) in `pkg/build/sbom_step_test.go`: flipping each input changes the checksum; identical inputs are stable. E2E: extend `test/e2e/sbom` with a toggle scenario (build → enable `packages` → rebuild → SBOM regenerated), modeled after `test/e2e/sbom/stage_dependencies_test.go` and the existing `type_change` fixtures.

**Rationale**: `calculateStableChecksum` is a pure function of its arguments — trivially table-testable. The existing `sbom_step_test.go` already tests checksum stability; extend it. The e2e proves the user-visible symptom (US1) end-to-end through the registry cache path.
