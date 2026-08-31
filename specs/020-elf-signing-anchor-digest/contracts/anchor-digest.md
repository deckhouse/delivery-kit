# Internal Contract: Anchor Digest Inputs

This is an internal package contract, not a public API or wire protocol.

## Contract

`calculateDigest(..., calculateDigestOptions{Anchor: true})` hashes the target platform, non-empty holistic inputs, applicable ELF signing identities, and the existing SBOM marker using the existing SHA3-224 input mechanism.

When ELF signing is enabled:

- `BsignEnabled` appends `PGPPrivateKeyFingerprint` with the non-anchor label `ELF_SIGNING_PGP_KEY_FINGERPRINT`.
- `InHouseEnabled` appends `ManifestSigningOptions.Signer().Cert()` with `MANIFEST_SIGNING_CERTIFICATE`.
- `InHouseEnabled` appends `ManifestSigningOptions.Signer().Chain()` with `SIGNING_CERTIFICATE_CHAIN`.

The anchor path must not append private keys, passphrases, or an independent signing enabled/disabled marker. The `sign` stage already accounts for its relevant manifest certificate and chain, so the anchor inputs must remain aligned with that existing checksum coverage rather than duplicating it under different labels or conditions.

## Compatibility

The change is internal and preserves public APIs, CLI syntax, dependencies, storage formats, and registry protocols.
