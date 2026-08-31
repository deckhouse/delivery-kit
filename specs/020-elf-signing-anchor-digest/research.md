# Research: ELF Signing Anchor Digest

## Decision: Extend the existing anchor branch of `calculateDigest`

- Add the applicable ELF signing identity values to the anchor input list in `pkg/build/build_phase.go`.
- Reuse the existing `signing.ELFSigningOptions` conditions and values already used by the non-anchor checksum path:
  - BSign enabled: `PGPPrivateKeyFingerprint`, labeled `ELF_SIGNING_PGP_KEY_FINGERPRINT`.
  - In-house signing enabled: `ManifestSigningOptions.Signer().Cert()`, labeled `MANIFEST_SIGNING_CERTIFICATE`.
  - In-house signing enabled: `ManifestSigningOptions.Signer().Chain()`, labeled `SIGNING_CERTIFICATE_CHAIN`.
- Keep the same ordered hash-input model used by the anchor path and continue omitting empty holistic inputs.

### Rationale

The non-anchor path at `calculateDigest` already defines the authoritative conditional checksum contract. Reusing its conditions, values, and labels prevents anchor/non-anchor drift and avoids introducing a new abstraction for only three inputs. The anchor digest is already the cache identity used by local and secondary stage storage lookup, so changing its inputs automatically changes cache eligibility without modifying storage or registry APIs.

### Alternatives considered

- **Add a separate signing-enabled marker:** rejected because the feature clarification explicitly requires no digest marker solely for signing state.
- **Include private key bytes or passphrases:** rejected because these are secrets and are not stable cache identities; the existing implementation exposes only the BSign fingerprint and certificate identities.
- **Refactor both paths into a shared helper:** rejected for this scoped change because the existing code is small and a helper would add abstraction without a current requirement. Tests will compare the anchor and non-anchor behavior directly.
- **Change the `sign` stage checksum:** rejected because `SignStage.GetDependencies` already accounts for its certificate and chain. The anchor path must document and align with that coverage, not duplicate or replace it.
- **Add E2E cache tests as the acceptance gate:** rejected as required coverage for this feature; focused unit tests are sufficient and avoid requiring signing tools or registry setup.

## Decision: Preserve the current public and dependency surface

Only private digest calculation behavior and co-located unit tests change. No CLI syntax, public API, external dependency, registry protocol, cryptographic operation, or secret handling changes.

## Decision: Use focused Ginkgo/Gomega tests

Extend the existing anchor digest test suite in `pkg/build/content_digest_test.go` with deterministic and sensitivity cases for each supported signing identity, disabled-signing secret exclusion, and alignment with the non-anchor formula.

### Rationale

The repository constitution requires co-located Ginkgo/Gomega tests. `calculateDigest` is private, so tests in package `build` can exercise the exact input contract without creating a new public seam or requiring a full build.
