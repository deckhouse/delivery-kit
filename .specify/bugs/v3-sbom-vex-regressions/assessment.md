# Bug Assessment: SBOM/VEX regressions in v3 migration

- **Slug**: v3-sbom-vex-regressions
- **Created**: 2026-08-28
- **Source**: pasted text
- **Verdict**: likely valid, needs reproduction
- **Severity**: high

## Report (verbatim or summarized)

Two related v3 migration regressions were reported:

1. In the multi-image VEX path, a missing stage descriptor can reach VEX convergence without validation and cause a panic instead of a descriptive error.
2. `werf sbom get` still calls the v2-era Kubernetes flag initializer even though the v3 command no longer registers the corresponding command infrastructure. This may fail during command construction or expose obsolete flags.

The report corresponds to review feedback for PR #225, “chore(release): merge werf v3 into delivery-kit”.

## Symptom

For a multi-platform image, VEX convergence may pass a nil stage descriptor to the VEX step. If the VEX implementation dereferences it, the command terminates with a runtime panic rather than returning an actionable error. The single-platform branch already returns an explicit error for the same missing-descriptor condition.

For `werf sbom get`, command initialization invokes `common.SetupKubeConnectionFlags`, despite the command otherwise using v3 build and registry initialization paths. Depending on the current `CmdData` and flag setup, invoking the command can register obsolete Kubernetes flags or fail before SBOM retrieval starts.

## Reproduction

### Multi-image VEX path

1. Configure a project with VEX enabled and more than one target platform.
2. Arrange for the image descriptors to be resolved from a cache or otherwise leave the `MultiplatformImage.stageDesc` unavailable.
3. Run the build/convergence path that calls VEX convergence.
4. Observe whether the command panics while processing a nil stage descriptor instead of returning an error naming the image.

The exact cache and registry setup required to produce the missing descriptor is **[NEEDS CLARIFICATION]**.

### `werf sbom get`

1. Invoke `werf sbom get` with a valid image name, `--tag`, or `--digest`.
2. Observe command construction and flag registration before SBOM retrieval.
3. Verify whether obsolete Kubernetes flags are registered or whether initialization fails before `runGet`, `runGetByTag`, or `runGetByDigest` executes.

The exact failure mode on the current binary is **[NEEDS CLARIFICATION]** and should be confirmed by running the command once.

## Suspected Code Paths

- `pkg/build/build_phase.go:1727-1773`, `convergeImageVex` — the `len(images) > 1` branch obtains `stageDesc` from `GetMultiplatformImage(name).GetStageDesc()` or from a newly constructed `MultiplatformImage`, but does not check the result before passing it to `vexStep.Converge`.
- `pkg/build/image/multiplatform_image.go:30-60`, `NewMultiplatformImage` — the constructor calculates the multi-platform digest and stage ID but does not set `stageDesc`; the fallback object therefore does not guarantee a non-nil descriptor. It can also panic when an image lacks a content-tag descriptor.
- `pkg/build/image/multiplatform_image.go:93-99`, `MultiplatformImage.GetStageDesc` — returns the stored `stageDesc` directly, including nil.
- `cmd/werf/sbom/get/get.go:123-125`, `NewCmd` — calls `common.SetupKubeConnectionFlags` during command construction even though the command's execution paths initialize werf and the Docker registry rather than Kubernetes.
- `cmd/werf/common/common.go:1169-1204`, `SetupKubeConnectionFlags` — registers Kubernetes connection flags and parses related environment configuration; this is the obsolete initialization called by `sbom get`.

## Root Cause Hypothesis

**Multi-image VEX, confidence: high.** The multi-image branch has no equivalent of the single-image nil guard. Both descriptor sources can yield nil, and the result is passed unconditionally to `vexStep.Converge`. The precise downstream panic depends on the VEX implementation, so runtime reproduction is still required.

**`sbom get`, confidence: medium-high.** The command explicitly calls the Kubernetes flag setup function at construction time, while its visible execution paths do not use Kubernetes initialization. The v3 migration removed or changed related command infrastructure, making this call stale. The exact impact—obsolete flags, initialization error, or an early panic—must be verified against the built command.

## Proposed Remediation

**Preferred**:

For multi-image VEX, validate `stageDesc` immediately after selecting it in both multi-image branches and return the same descriptive error used by the single-image branch when it is nil. Then add a regression test that constructs a multi-image convergence scenario with no available stage descriptor and asserts an error rather than a panic. Separately, investigate why the multi-platform fallback has no descriptor; if a valid descriptor is required for VEX, prefer obtaining it from the established image graph or cached content descriptor rather than relying on a newly constructed object whose `stageDesc` is unset.

For `werf sbom get`, remove the stale `common.SetupKubeConnectionFlags` call from `NewCmd` if the command has no Kubernetes dependency. Execute the command after the change and add a command-construction/flag test that verifies the intended v3 flags are available without requiring Kubernetes initialization.

**Alternatives**:

- Centralize descriptor validation in `vexStep.Converge` and make it return an error for nil descriptors. This protects all callers but weakens the local diagnostic context and does not address the questionable multi-platform fallback.
- Keep the Kubernetes flag setup but make it conditional on an actual Kubernetes-dependent execution path. This preserves compatibility for a legitimate use case, but adds complexity and risks retaining obsolete v2 behavior; removal is preferable if SBOM retrieval is registry/build based only.

**Files likely to change**:

- `pkg/build/build_phase.go`
- `pkg/build/build_phase_test.go` or the existing VEX-specific test file, if present
- `cmd/werf/sbom/get/get.go`
- `cmd/werf/sbom/get/get_test.go`

**Tests to add or update**:

- Multi-image VEX convergence with a nil multi-platform stage descriptor returns a descriptive error and never panics.
- Multi-image VEX convergence with a valid descriptor still calls convergence successfully.
- `sbom get` command construction succeeds without Kubernetes initialization.
- `sbom get` exposes only the intended flags and can proceed to the registry/build path for `--tag`, `--digest`, and image-name modes.

## Risks & Considerations

- Returning an error instead of panicking changes failure behavior but is required for safe diagnostics and should not hide the underlying missing-descriptor condition.
- Removing Kubernetes flag registration may be user-visible if undocumented scripts currently pass those flags to `werf sbom get`; verify the v3 command contract and generated CLI documentation before finalizing.
- The multi-platform fallback may reveal a deeper lifecycle issue in how `MultiplatformImage.stageDesc` is populated after cache hits. A nil guard alone prevents the crash but may leave VEX convergence unavailable for a valid build.
- Tests must cover warm-cache and multi-platform paths, not only direct nil input, to avoid proving a synthetic condition while missing the migration regression.

## Open Questions

- [NEEDS CLARIFICATION: Which exact cache/registry state leaves the multi-platform `stageDesc` unavailable?]
- [NEEDS CLARIFICATION: Does `vexStep.Converge` dereference `stageDesc` directly, and what exact panic occurs?]
- [NEEDS CLARIFICATION: On the current v3 binary, does `werf sbom get` fail during flag registration, expose obsolete Kubernetes flags, or merely register unused flags?]
- [NEEDS CLARIFICATION: Are any Kubernetes flags intentionally part of the documented `werf sbom get` interface?]
