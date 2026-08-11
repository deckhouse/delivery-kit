# Tasks: SBOM Artifact Storage Model

All tasks completed — reverse-engineered from the implemented feature (branch `refactor/sbom/artifact-storage-format`, PR #222).

## Phase 1: Self-describing artifact manifest

- [x] T001 Extract `buildArtifactImage` in `pkg/oci/artifact/store.go`: payload layer, `types.OCIManifestSchema1`, artifact type as config media type
- [x] T002 Write werf annotations (`io.werf.image-name`, `io.werf.checksum`, `io.werf.target-platform`) into the artifact manifest via `mutate.Annotations`; extract `artifactAnnotations`
- [x] T003 Drop the now-unused `EmptyConfigMediaType` constant
- [x] T004 Unit specs for manifest contents in `store_internal_test.go`: annotations present, artifact type resolvable via `partial.ArtifactType`, distinct digests for artifacts differing only by image name
- [x] T005 Integration spec: pushed artifact manifest carries annotations, config media type, and `subject` (`attach_integration_test.go`)

## Phase 2: One entry per artifact

- [x] T006 Evict index entries by manifest digest in `updateFallbackIndex` (`pkg/oci/artifact/fallback.go`)
- [x] T007 Deduplicate reads by digest in `matchDescriptors`, preferring the werf-annotated descriptor
- [x] T008 Fix fixtures in `fallback_internal_test.go` that shared one digest across distinct artifacts (described the previous manifest format); add `digestForName`
- [x] T009 Integration spec: no duplicate entry left by go-containerregistry (`attach_integration_test.go`)

## Phase 3: Convergent attach

- [x] T010 Replace the byte-identical index check with `attachDescriptor`: republish-and-merge until the index resolves the artifact key to the attached descriptor, exponential backoff 500ms/30s (`fallback.go`)
- [x] T011 Split key matching: `isArtifactKey` (exact, writers) vs `matchDescriptors` (empty-name wildcard, readers); require the key to resolve uniquely in `isAttached`
- [x] T012 Move the tag lock to span the artifact push: `withTagLock` in `store.go`; unexport `Attach` as `attachDescriptor`
- [x] T013 Verify immediately after each push so the happy path converges without backoff sleeps
- [x] T014 Unit specs for `isAttached` including unnamed artifacts, stale entries, and foreign same-digest descriptors (`fallback_internal_test.go`)
- [x] T015 Integration specs: entry restored after another writer replaced the whole index (via `clobberIndex`), reattach replaces instead of accumulating, unnamed artifact next to named ones (`attach_integration_test.go`)
- [x] T016 Remove the `retry timeout` spec that exercised the backoff library with a hardcoded message and asserted nothing about werf code (`fallback_test.go`)

## Phase 4: Referrers API forward compatibility

- [x] T017 Specs against a referrers-capable fake registry (`registry.WithReferrersSupport(true)`): artifact listed by the Referrers API, artifact type resolved from config media type, tag-based index still maintained, annotations present on the stored manifest (`referrers_compat_test.go`)

## Phase 5: Validation

- [x] T018 `task format`, `task build`, `task lint`, `task test:unit paths="./pkg/oci/... ./pkg/sbom/... ./pkg/storage/..."` — clean; 62 specs in `pkg/oci/artifact`
- [x] T019 E2E on CI

## Dependencies

- Phase 2 depends on Phase 1: digest-based deduplication is sound only because annotations are part of the manifest (distinct artifacts ⇒ distinct digests).
- Phase 3 (T011) depends on Phase 2: in the unnamed case the go-containerregistry descriptor is indistinguishable from werf's by key, so `isAttached` must require unique resolution.

## Implementation strategy

Identity first, then deduplication, then convergence — each phase makes the next one safe. The whole change is confined to `pkg/oci/artifact`; consumers observe the same API with `Attach` reduced to the `OCIStore` method.
