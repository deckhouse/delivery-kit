# Feature Specification: ELF Signing Anchor Digest

**Feature Branch**: `020-elf-signing-anchor-digest`

**Created**: 2026-08-31

**Status**: Draft

**Input**: Extracted from PR #279 specification; scope limited to ELF signing inputs in the anchor digest.

## Project Context

Delivery Kit builds container images and reuses results from local and remote caches. An anchor digest identifies the cacheable result of an anchor stage. The digest is therefore a cache contract: if ELF signing configuration can change the resulting image or its security metadata, changing the applicable signing identity must make the previous anchor result ineligible for reuse.

This feature covers the stable, non-secret ELF signing inputs needed for anchor cache identity:

- the BSign key fingerprint when BSign is enabled;
- the in-house signing certificate when in-house signing is enabled;
- the in-house signing certificate chain when in-house signing is enabled.

Secret key material, passphrases, cryptographic implementation, and registry protocol changes are outside this feature.

## Clarifications

### Session 2026-08-31

- The anchor digest must include stable, non-secret ELF signing identities so key rotation and certificate changes invalidate incompatible cached results.
- Anchor ELF signing inputs must use the same conditional values and labels as the corresponding non-anchor checksum contract.
- The anchor contract must not add a separate digest marker solely for signing being enabled or disabled; it must represent the applicable stable checksum components.
- End-to-end cache validation is optional follow-up coverage; focused unit tests are the required acceptance gate.
- Q: Should enabling or disabling ELF signing itself change the anchor digest if the fingerprint, certificate, and certificate chain remain unchanged? → A: No, no separate enabled/disabled marker is added; only the applicable fingerprint, certificate, and certificate chain are included.
- Q: If ELF signing is enabled but the applicable stable signing inputs do not change or are absent, should cache reuse be allowed? → A: Yes, cache reuse is allowed; the digest does not receive a separate signing marker, and unchanged stable inputs do not prohibit reuse.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Invalidate anchors when BSign identity changes (Priority: P1)

As a security-conscious release engineer, I want an anchor cache entry to reflect the BSign key identity so that rotating the signing key cannot reuse an anchor produced for a different signer.

**Why this priority**: Reusing an anchor after signing-key rotation can return an artifact with incompatible security metadata.

**Independent Test**: Calculate the anchor digest with BSign enabled and two different key fingerprints; verify that the digests differ, while repeated calculations with the same fingerprint remain deterministic.

**Acceptance Scenarios**:

1. **Given** BSign is enabled and all other anchor inputs are unchanged, **When** the key fingerprint changes, **Then** the anchor digest changes and the previous incompatible result is not reused.
2. **Given** BSign is enabled with the same key fingerprint, **When** the anchor digest is calculated repeatedly, **Then** the digest is stable.
3. **Given** BSign is disabled, **When** the private key or passphrase changes, **Then** the anchor digest does not change because secret signing material is not a cache identity input.

---

### User Story 2 - Invalidate anchors when in-house signing identity changes (Priority: P1)

As a release engineer using in-house ELF signing, I want changes to the signing certificate or certificate chain to invalidate the anchor cache so that the reused result matches the requested signing identity.

**Why this priority**: A stale anchor can bypass a requested certificate or trust-chain change even when ordinary image contents are unchanged.

**Independent Test**: Calculate the anchor digest with in-house signing enabled, changing one certificate input at a time, and verify that each applicable change produces a different anchor identity.

**Acceptance Scenarios**:

1. **Given** in-house signing is enabled and all other inputs are unchanged, **When** the signing certificate changes, **Then** the anchor digest changes.
2. **Given** in-house signing is enabled and all other inputs are unchanged, **When** the certificate chain changes, **Then** the anchor digest changes.
3. **Given** the in-house signing certificate and chain are unchanged, **When** the anchor digest is calculated repeatedly, **Then** the digest remains deterministic.

---

### User Story 3 - Keep anchor and non-anchor signing contracts aligned (Priority: P2)

As a maintainer, I want anchor signing inputs to follow the existing non-anchor checksum contract so that cache invalidation rules remain consistent and do not diverge between digest paths.

**Why this priority**: Divergent rules can make one cache path accept an artifact that another path would invalidate.

**Independent Test**: Compare anchor and non-anchor checksum inputs while varying each supported ELF signing identity, verifying that the same conditions, labels, and values are used without duplicate or secret-bearing inputs.

**Acceptance Scenarios**:

1. **Given** BSign is enabled, **When** the BSign fingerprint changes, **Then** both applicable digest paths respond according to the same fingerprint input contract.
2. **Given** in-house signing is enabled, **When** the certificate or chain changes, **Then** the anchor path uses the same corresponding inputs as the non-anchor path.
3. **Given** signing is absent or disabled, **When** no applicable stable signing identity exists, **Then** the anchor path does not add a separate enabled/disabled marker.

---

### Edge Cases

- Rotating BSign signing material without changing ordinary source inputs invalidates the relevant anchor result through the stable fingerprint.
- Changing only a private key or passphrase does not become a cache identity input.
- Enabling signing on a previously warmed unsigned cache may reuse the existing result when no applicable stable signing identity changes; when an applicable identity changes or is introduced, the anchor digest must change.
- Disabling signing after a signed cache hit may reuse the existing result when no applicable stable signing identity changes; conflicting applicable signing identities must produce a different digest.
- A remote registry cache hit and a local cache hit follow the same ELF signing invalidation semantics.
- Repeated builds with identical complete applicable inputs remain deterministic.
- A failed signing operation fails clearly and does not publish or mark an invalid result as reusable.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The anchor digest MUST include the BSign key fingerprint when BSign is enabled, using the existing non-anchor checksum label and value.
- **FR-002**: The anchor digest MUST include the in-house signing certificate when in-house signing is enabled, using the existing non-anchor checksum label and value.
- **FR-003**: The anchor digest MUST include the in-house signing certificate chain when in-house signing is enabled, using the existing non-anchor checksum label and value.
- **FR-004**: Changing any applicable ELF signing checksum component MUST produce a different anchor digest and prevent reuse of an incompatible anchor result.
- **FR-005**: The ELF signing cache identity MUST use stable non-secret identities and MUST NOT include private key bytes, passphrases, or other secret key material.
- **FR-006**: The anchor cache-key contract MUST use the same conditional ELF signing inputs as the non-anchor checksum contract and MUST preserve their labels and values.
- **FR-007**: The anchor contract MUST NOT add a separate digest marker or mode tag solely to represent signing as absent, disabled, or enabled; digest changes caused by signing configuration MUST come only from applicable fingerprint, certificate, or certificate-chain values.
- **FR-008**: Components already accounted for by the `sign` stage MUST NOT be duplicated or represented inconsistently in the anchor contract.
- **FR-009**: The system MUST preserve cache reuse when all applicable anchor inputs and ELF signing identities are unchanged.
- **FR-010**: A signing failure MUST be reported as an actionable build failure and MUST NOT silently fall back to an incompatible cached result.
- **FR-011**: Focused unit tests MUST verify deterministic anchor digests for identical applicable signing inputs and changed digests when each supported ELF signing identity changes.
- **FR-012**: Focused unit tests MUST verify that private key material and passphrases do not affect the anchor digest.
- **FR-013**: Focused unit tests MUST verify alignment of anchor ELF signing inputs with the corresponding non-anchor checksum contract, including BSign fingerprint and in-house certificate/chain values.
- **FR-014**: The implementation MUST keep the public API, CLI syntax, and external dependency set unchanged.
- **FR-015**: The digest calculation MUST document that the `sign` stage already accounts for its relevant checksum components, including the manifest signing certificate and certificate chain, so anchor inputs do not duplicate or diverge from that contract.

### Key Entities

- **Anchor result**: A build result identified by the inputs that determine whether it is safe and correct to reuse.
- **Anchor digest**: The stable identity derived from the complete applicable anchor inputs and used for cache lookup and reuse.
- **ELF signing checksum components**: The conditionally included stable non-secret values used by the existing checksum contract: BSign key fingerprint, in-house signing certificate, and in-house certificate chain.
- **Cache source**: The local or remote store from which a previously built result may be resolved.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of focused unit-test cases, changing an applicable BSign key fingerprint changes the anchor digest.
- **SC-002**: In 100% of focused unit-test cases, changing the in-house signing certificate changes the anchor digest when in-house signing is enabled.
- **SC-003**: In 100% of focused unit-test cases, changing the in-house certificate chain changes the anchor digest when in-house signing is enabled.
- **SC-004**: In 100% of focused unit-test cases with identical complete applicable inputs, the anchor digest is deterministic.
- **SC-005**: Focused unit tests demonstrate that private keys and passphrases are excluded from the anchor digest.
- **SC-006**: Focused unit tests demonstrate that anchor signing inputs use the same conditions, labels, and values as the non-anchor checksum contract without a separate signing-state marker.
- **SC-007**: The digest implementation documents the existing `sign` stage checksum coverage, preventing duplicate or inconsistent signing inputs.
- **SC-008**: No public command syntax, external API, or dependency changes are introduced by this feature.

## Assumptions

- The existing non-anchor checksum contract defines the authoritative conditions, labels, and stable values for BSign fingerprint, in-house signing certificate, and certificate chain.
- The `sign` stage already accounts for its relevant manifest signing certificate and certificate-chain components; the anchor path must remain aligned without duplicating them inconsistently.
- Focused unit tests can vary the applicable signing identities without changing unrelated anchor inputs.
- Local-cache and registry-backed E2E validation may be added when the prepared environment supports it, but E2E is not required for acceptance.
- This feature covers cache identity and reuse correctness; ELF signing implementation, key storage, cryptographic algorithms, and registry protocols are out of scope.
