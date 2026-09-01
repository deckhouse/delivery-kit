# Existing integration inventory

- `pkg/build/build_phase.go`: `BeforeImages` initializes storage; `AfterImages` publishes primary/final images and then runs SBOM and VEX convergence. `convergePlatformImageSbom` currently owns SBOM propagation. `convergeImageVex` publishes VEX but has no propagation path. `findAndFetchStageFromSecondaryStagesStorage` copies restored stages into primary and then cache storage.
- `pkg/build/sbom_step.go`: `ConvergeWithMerge` computes the stable checksum, checks the fallback artifact index, generates and pushes CycloneDX, and `PropagateArtifacts` copies attached artifacts to final/cache destinations.
- `pkg/build/vex_step.go`: `Converge` computes VEX checksum, checks the fallback artifact index, and pushes OpenVEX. It requires a non-nil stage descriptor.
- `pkg/build/stage/base.go` and `sign.go`: stages expose buildable/mutable flags, dependencies, image preparation, and registry-side mutation. Signing is the existing non-buildable mutable registry-stage pattern.
- `pkg/oci/artifact/copy.go`: `CopyAttachedArtifacts` already copies all typed fallback-index artifacts by payload, supports differing source/destination digests, skips equivalent identities, and treats a missing source index as a no-op.
- `pkg/storage/manager`: final and cache stage-copy operations are separate; cache errors are logged as warnings and final errors are returned. Secondary restoration uses `CopySuitableStageDescByDigest` and then copies the restored stage into caches.
- `pkg/cleaning/cleanup.go`: orphan artifact indexes are cleaned independently for primary, final, and configured cache repositories.
- Existing tests: Ginkgo/Gomega tests cover SBOM/VEX convergence guards, fallback-index convergence, artifact copy idempotency, differing destination digests, concurrent attachment, and orphan cleanup. Existing e2e suites are under `test/e2e/sbom` and `test/e2e/vex`.

## Foundation decisions applied

- Reuse `artifact.CopyAttachedArtifacts` as the shared kind-neutral propagation primitive rather than introducing another artifact store.
- Keep final propagation errors fatal and cache propagation best effort.
- Perform local-only validation before storage initialization whenever SBOM or an image-level VEX document is enabled.
