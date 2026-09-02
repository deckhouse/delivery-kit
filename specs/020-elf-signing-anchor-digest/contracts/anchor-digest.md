# Internal Contract: Anchor Digest Inputs

This is an internal package contract, not a public API or wire protocol.

## Contract

`calculateDigest(..., calculateDigestOptions{Anchor: true})` hashes the target platform, non-empty holistic inputs, applicable ELF signing identities, and the existing SBOM marker using the existing SHA3-224 input mechanism.

When ELF signing is enabled:

- `BsignEnabled` appends `PGPPrivateKeyFingerprint`.
- `InHouseEnabled` appends `ManifestSigningOptions.Signer().Cert()`.
- `InHouseEnabled` appends `ManifestSigningOptions.Signer().Chain()`.

The anchor path must not append private keys, passphrases, labels, or an independent signing enabled/disabled marker. The `sign` stage already accounts for its relevant manifest certificate and chain, so the anchor inputs must remain aligned with that existing checksum coverage.

## Compatibility

The change is internal and preserves public APIs, CLI syntax, dependencies, storage formats, and registry protocols.
