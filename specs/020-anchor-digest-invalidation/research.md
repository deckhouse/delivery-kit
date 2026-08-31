# Research: Systemic Anchor Digest Invalidation

## Decision: Extend the existing anchor digest input list with the complete cache contract

- **Finding:** `pkg/build/build_phase.go` uses a separate anchor branch in `calculateDigest`. That branch currently hashes target platform, non-empty holistic inputs, and the SBOM marker, then returns before the ordinary `imagePkg.BuildCacheVersion` and ELF-signing inputs are appended.
- **Decision:** Keep `calculateDigest` as the single digest implementation and add the documented cache-version and ELF-signing identity inputs to the anchor branch before hashing. Preserve the existing non-anchor argument order and behavior.
- **Rationale:** This fixes the early-return root cause without changing the public API or duplicating digest logic.
- **Alternatives considered:** Moving all anchor inputs into a new public cache-key type; rejected because it expands the API and is unnecessary for the current defect.

## Decision: Represent ELF signing as explicit mode plus stable identity

- **Finding:** `signing.ELFSigningOptions` exposes `InHouseEnabled`, `BsignEnabled`, and `PGPPrivateKeyFingerprint`. The CLI derives the BSign fingerprint from the supplied key and already passes signing options into build calculation. In-house signing currently uses certificate and chain values in the non-anchor digest path.
- **Decision:** Make the anchor path use the same conditional signing inputs and component labels as the non-anchor path: `ELF_SIGNING_PGP_KEY_FINGERPRINT`, `MANIFEST_SIGNING_CERTIFICATE`, and `SIGNING_CERTIFICATE_CHAIN`. Do not add a separate enabled/disabled marker or signing-mode tag. Never add passphrases or private key bytes.
- **Rationale:** This keeps anchor and non-anchor checksum contracts aligned and avoids introducing an anchor-only representation of signing state. Changes to the existing stable identities still affect the digest when signing is enabled.
- **Alternatives considered:** Hashing the private key or passphrase; rejected as secret leakage and explicitly out of scope. Adding explicit disabled/mode markers; rejected because the required behavior is to mirror the existing non-anchor checksum inputs rather than encode the enabled/disabled fact separately.

## Decision: Keep the public API unchanged

- **Finding:** `calculateDigest` and `calculateDigestOptions` are internal to `pkg/build`; CLI signing flags already provide the required configuration. No external consumer needs a new parameter.
- **Decision:** Change only internal digest construction and tests.
- **Rationale:** Satisfies FR-015 and minimizes compatibility risk.

## Decision: Unit tests use the repository's Ginkgo/Gomega style; E2E is optional follow-up coverage

- **Finding:** `pkg/build/stage/content_digest_test.go` demonstrates Ginkgo/Gomega digest sensitivity tests, while `test/e2e/build/content_tag_test.go` verifies warmed local content-tag reuse and `test/e2e/build/signature_test.go` provides signing fixtures and CLI arguments.
- **Decision:** Add focused Ginkgo/Gomega tests for anchor digest determinism, explicit cache-version sensitivity, and matching ELF checksum inputs. Keep warmed-cache E2E as optional follow-up coverage.
- **Rationale:** The required scope is the digest contract and its unit-level behavior; the E2E flow is useful but no longer a mandatory gate.
- **Alternatives considered:** Making E2E mandatory or testing only image signatures; rejected because E2E is explicitly out of the required scope and image signatures do not isolate the digest contract.

## Decision: Registry-backed validation is additive, not mandatory

- **Finding:** Existing content-tag E2E coverage exercises local cache and optionally explicit registry repositories. The feature clarification makes local cache mandatory and registry coverage conditional on prepared environment support.
- **Decision:** Make the local warmed-cache scenario the required test; reuse existing `--repo`/registry setup only as an additional case if the fixture can support it without weakening the local test.
- **Rationale:** Keeps the acceptance gate deterministic while preserving coverage of the same digest semantics across storage sources where available.
