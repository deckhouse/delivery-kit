# Feature Specification: Systemic Anchor Digest Invalidation

**Feature Branch**: `020-anchor-digest-invalidation`

**Created**: 2026-08-31

**Status**: Draft

**Input**: User description: "Ознакомиться с контекстом Anchor Digest Build Cache Version, разработать системное решение, которое проверяет весь flow через E2E и закрывает кейсы ELF signing и BuildCacheVersion в anchor digest."

## Project Context

Delivery Kit builds container images and reuses results from local and remote caches. An anchor digest identifies the cacheable result of an anchor stage. The digest is therefore a cache contract: if an input can change the resulting image or its security metadata, changing that input must make the previous anchor result ineligible for reuse.

The feature addresses two cache-affecting inputs:

- **Build cache schema/version**: a version change is an explicit invalidation mechanism for changes in cache semantics or representation.
- **ELF signing configuration**: the signing mode and stable non-secret key fingerprint or identifier are cache-affecting inputs. Secret key material and other signing parameters are outside this feature's cache identity contract.

The solution must keep the cache-key contract verifiable through focused unit tests. End-to-end validation is optional for these changes and is not a release-blocking requirement.

## Clarifications

### Session 2026-08-31

- Q: Should the anchor digest include the ELF signing key's fingerprint or stable identifier so that key rotation always invalidates the cache? → A: Yes — include a stable non-secret fingerprint or key identifier; do not include secret material in the digest.
- Q: Which ELF signing configuration changes, besides enabling/disabling signing and changing the key fingerprint, should invalidate the anchor digest? → A: Only the signing mode and key fingerprint; other parameters are outside this feature's cache identity contract.
- Q: Should the mandatory E2E scenario specifically test a registry-backed cache rather than only a local cache? → A: E2E tests are not mandatory for these changes; if added, a local cache is sufficient and registry-backed cache may be tested when available in the prepared environment.
- Follow-up decision: E2E tests are removed from the mandatory acceptance scope for these changes; focused unit tests are the required validation.
- Follow-up decision: The anchor ELF signing checksum inputs must be aligned with the corresponding non-anchor inputs, while avoiding duplication of components already accounted for by the `sign` stage.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Invalidate anchors when the build cache version changes (Priority: P1)

As a build or release engineer, I want changing the build cache version to invalidate anchor results so that a cache format or build-logic change cannot silently reuse an incompatible image.

**Why this priority**: Reusing an anchor produced under an older cache contract can produce stale or incompatible build outputs. This is the primary correctness and emergency-invalidation requirement.

**Independent Test**: Calculate the anchor digest twice with identical inputs and once with only the build cache version changed, then verify determinism and invalidation without requiring an end-to-end build.

**Acceptance Scenarios**:

1. **Given** the same anchor inputs are calculated with cache version A and cache version B, **When** the versions differ, **Then** the resulting anchor digests differ.
2. **Given** the same project inputs, signing configuration, and cache version are supplied twice, **When** the anchor digest is calculated, **Then** both calculations produce the same digest.
3. **Given** the cache version is changed, **When** the anchor digest inputs are inspected, **Then** the explicitly supplied version is present in the anchor checksum contract.

---

### User Story 2 - Invalidate anchors when ELF signing changes (Priority: P1)

As a security-conscious release engineer, I want anchor cache reuse to reflect ELF signing configuration and signing material so that a build cannot return an unsigned or differently signed image from a stale cache entry.

**Why this priority**: A cache hit that bypasses a requested signing change is a security and supply-chain correctness failure, even when the ordinary image contents appear unchanged.

**Independent Test**: Calculate the anchor digest with signing disabled, enabled, and enabled with a changed key fingerprint, then verify that compatible inputs remain deterministic and incompatible inputs produce different anchor identities. Cryptographic signature verification and end-to-end cache validation are outside this feature's required test scope.

**Acceptance Scenarios**:

1. **Given** the same anchor inputs are calculated with ELF signing disabled and enabled, **When** the signing mode differs, **Then** the resulting anchor digests differ.
2. **Given** the same anchor inputs are calculated with two different ELF signing key fingerprints, **When** the fingerprint differs, **Then** the resulting anchor digests differ.
3. **Given** ELF signing mode and key fingerprint are unchanged, **When** the anchor digest is calculated repeatedly, **Then** the digest remains deterministic. Cryptographic signature verification and end-to-end cache validation are out of scope.

---

### User Story 3 - Preserve complete cache behavior across anchor and non-anchor stages (Priority: P2)

As a maintainer, I want cache-affecting inputs to be represented consistently in every applicable digest path so that fixing anchor invalidation does not regress ordinary stage caching or create divergent rules that are difficult to evolve.

**Why this priority**: Anchor and non-anchor stages are different cache paths, but both must remain correct when cache schema or signing inputs change.

**Independent Test**: Compare anchor and non-anchor digest inputs while varying one cache-affecting input at a time.

**Acceptance Scenarios**:

1. **Given** a non-anchor cache result exists, **When** the build cache version changes, **Then** the existing non-anchor invalidation behavior remains intact.
2. **Given** an anchor and non-anchor result are generated from identical applicable inputs, **When** an input changes, **Then** each path either changes its digest or rejects the old cache result according to its cache contract.
3. **Given** unrelated or empty optional inputs are unchanged, **When** the feature is applied, **Then** existing deterministic digest behavior is preserved.

---

### Edge Cases

- A cache entry created before the new invalidation inputs were included must not be treated as a valid match merely because all previously supported inputs match.
- An empty or omitted optional signing configuration must be represented consistently; it must not collide with a distinct configured signing state.
- Rotating signing material without changing ordinary source inputs must invalidate the relevant anchor result.
- Enabling signing on a previously warmed unsigned cache must not return the unsigned result.
- Disabling signing after a signed cache hit must not return the signed result when the requested output is unsigned.
- A remote registry cache hit and a local cache hit must follow the same invalidation semantics.
- Repeated builds with identical complete inputs must remain deterministic.
- A failed signing operation must fail the build clearly and must not publish or mark an invalid result as reusable.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST treat the build cache version as part of the identity of every anchor result for which the version can affect cache validity.
- **FR-002**: Changing the build cache version MUST prevent reuse of an anchor result created under a different version.
- **FR-003**: The anchor ELF signing checksum inputs MUST be aligned with the corresponding non-anchor checksum inputs: include the Bsign key fingerprint when Bsign is enabled, and include the in-house signing certificate and certificate chain when in-house signing is enabled; components already included by the `sign` stage MUST NOT be duplicated in the anchor contract.
- **FR-004**: Changing any applicable ELF signing checksum component — the Bsign key fingerprint, in-house signing certificate, or in-house certificate chain — MUST produce a different anchor digest and prevent reuse of the previous incompatible anchor result. The contract MUST NOT add a digest difference solely to record that signing was enabled or disabled.
- **FR-004a**: For ELF signing key rotation, the system MUST use a stable non-secret key fingerprint or identifier in cache identity and MUST NOT include secret key material. Other ELF signing parameters are outside this feature's cache identity contract.
- **FR-005**: The system MUST preserve cache reuse when all cache-affecting inputs, including build cache version and all applicable ELF signing checksum components, are identical.
- **FR-006**: The system MUST apply one explicit, documented cache-key contract to anchor digest calculation rather than relying on an implicit fallback that hides a required input from the caller or test contract.
- **FR-006a**: The build cache version MUST be propagated as an explicit input through the complete internal digest-calculation flow into the anchor digest calculation; `calculateDigest` MUST consume the value supplied by its caller and MUST NOT obtain it indirectly from package-global state or another hidden fallback.
- **FR-007**: The anchor cache-key contract MUST use the same conditional ELF signing inputs as the non-anchor checksum contract and MUST NOT add a separate marker for absent, disabled, or enabled signing.
- **FR-008**: The system MUST preserve the existing behavior of non-anchor digest calculation unless an input is demonstrably required by that path's cache contract.
- **FR-009**: Unit tests MUST verify deterministic anchor digests for identical complete inputs and different anchor digests when the build cache version changes.
- **FR-010**: Unit tests MUST verify that changing each supported ELF signing checksum component affecting anchor output changes the anchor identity or otherwise rejects the incompatible cache result; enabled/disabled state alone is not an independent digest input.
- **FR-011**: Focused unit tests MUST verify that changing the explicitly supplied build cache version changes the anchor digest; E2E validation is not required for these changes.
- **FR-012**: Focused unit tests MUST verify anchor alignment with the non-anchor ELF checksum inputs, including changed key fingerprints and in-house certificate/chain values; cryptographic signature verification and E2E validation are out of scope.
- **FR-013**: Unit tests MUST cover the anchor digest contract directly, including alignment of the anchor ELF signing inputs with the corresponding non-anchor inputs. Local-cache and registry-backed E2E validation are optional.
- **FR-014**: The system MUST report an actionable failure when the requested signing operation cannot be completed, without silently falling back to an incompatible cached result.
- **FR-015**: The implementation MUST not require a new external dependency and MUST keep the public API unchanged unless a documented compatibility need is identified during planning.
- **FR-016**: The `calculateDigest` function MUST include a concise code comment explaining that the `sign` stage already accounts for its relevant checksum components, including the manifest signing certificate and certificate chain, so the anchor digest uses the same components without duplicating or diverging from that checksum contract.

### Key Entities

- **Anchor result**: A build result identified by the inputs that determine whether it is safe and correct to reuse.
- **Anchor digest**: The stable identity derived from the complete applicable anchor inputs and used for cache lookup and reuse.
- **Build cache version**: The explicit version of cache semantics or representation used to invalidate results after a cache contract change.
- **ELF signing checksum components**: The conditionally included stable non-secret values used by the existing checksum contract: Bsign key fingerprint, in-house signing certificate, and in-house certificate chain.
- **Cache source**: The local or remote store from which a previously built result may be resolved.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of focused unit-test cases, changing only the explicitly supplied build cache version changes the anchor digest.
- **SC-002**: In 100% of focused unit-test cases, changing an applicable ELF signing checksum component changes the anchor digest; enabling or disabling signing alone is not encoded as a separate marker.
- **SC-003**: In 100% of focused unit-test cases with identical complete inputs, the anchor digest is deterministic.
- **SC-004**: Focused unit tests cover cache-version change, Bsign fingerprint rotation, and in-house certificate/chain changes in the anchor digest contract, with the anchor inputs aligned to the non-anchor contract.
- **SC-005**: The digest implementation documents which signing components are already accounted for by the `sign` stage, preventing duplicate or inconsistent checksum inputs.
- **SC-006**: Optional E2E tests, if run, do not reveal a cache hit that violates the requested cache version or signing state; their execution is not required for this feature's acceptance.
- **SC-008**: The affected unit tests complete without introducing a new external dependency or changing existing user-facing command semantics.
- **SC-007**: Unit coverage demonstrates that changing the explicitly supplied build cache version changes the anchor digest without mutating or relying on hidden global state.

## Assumptions

- Focused unit tests can vary the explicit cache version and signing inputs without changing unrelated project inputs; the digest calculation flow exposes the cache version explicitly to the anchor calculation.
- The `sign` stage already includes its relevant manifest signing certificate and certificate-chain components in its own checksum inputs.
- End-to-end cache testing may use existing project fixtures when practical, but it is optional and not a prerequisite for acceptance.
- If E2E tests are added, local cache is sufficient; registry-backed cache testing uses the prepared test registry when that path is available.
- The feature covers cache identity and end-to-end reuse correctness; it does not redesign ELF signing, key storage, cryptographic algorithms, or registry protocols.
- Secret ELF signing key material is never placed in a digest; cache identity uses the existing supported stable key fingerprint or equivalent non-secret identifier.
- Existing unrelated changes in the repository, including wiki artifacts, are outside this feature's scope.
