# Data Model: Anchor Digest Invalidation

## Anchor result

A cached build-stage result eligible for lookup by an anchor digest.

- **Identity:** anchor digest.
- **Source:** local cache, with registry-backed cache as an additional supported source.
- **Validity rule:** reusable only when the complete applicable cache-key contract matches the requested build.
- **Failure rule:** a signing failure aborts the build; it must not produce a reusable result.

## Anchor digest

A deterministic SHA3-224 identity calculated from the ordered anchor cache-key inputs.

- **Required inputs:** target platform; holistic build inputs; build cache version.
- **Conditional input:** SBOM-enabled marker when SBOM is enabled.
- **Signing inputs:** the same conditional stable non-secret values and checksum labels used by the non-anchor path: `ELF_SIGNING_PGP_KEY_FINGERPRINT`, `MANIFEST_SIGNING_CERTIFICATE`, and `SIGNING_CERTIFICATE_CHAIN`.
- **Normalization:** empty optional holistic inputs are omitted according to the existing anchor behavior; the anchor path does not add a separate marker for signing being enabled or disabled.
- **Determinism:** identical complete inputs produce the same digest.
- **Invalidation:** changing build cache version, signing mode, or signing key identity changes the digest or makes the old result ineligible.
- **Secrets:** private key bytes and passphrases are excluded.

## Build cache version

The existing `imagePkg.BuildCacheVersion` value representing the cache semantics/representation contract.

- Included in anchor identity.
- Existing non-anchor inclusion remains unchanged.
- Any value change invalidates prior anchor results.

## ELF signing checksum inputs

The anchor path mirrors the existing non-anchor checksum contribution.

- Include `PGPPrivateKeyFingerprint` under the existing BSign-enabled condition.
- Include the signer certificate under `MANIFEST_SIGNING_CERTIFICATE` when in-house signing is enabled.
- Include the signer chain under `SIGNING_CERTIFICATE_CHAIN` when in-house signing is enabled.
- Do not append a separate enabled/disabled marker or mode tag.
- Do not include private key material or passphrases.
- Changing any included stable identity changes the anchor digest when its existing condition is active.

## Relationships and flow

`BuildOptions.ELFSigningOptions` and the existing build cache version feed `calculateStage`; `calculateStage` passes them to `calculateDigest`; the resulting anchor digest is used by storage lookup and stage reuse. No new persisted schema or public API is introduced.
