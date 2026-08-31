# Anchor Cache-Key Contract

This feature does not add a public API or CLI flag. This document defines the internal contract that `calculateDigest` must implement and that tests must preserve.

## Ordered identity inputs

The anchor digest is the SHA3-224 hash of the existing anchor inputs plus the following explicit, tagged values in a stable order:

1. target platform;
2. non-empty holistic inputs, in their existing order;
3. build cache version;
4. the existing conditional ELF checksum inputs, using the same labels and values as the non-anchor path: `ELF_SIGNING_PGP_KEY_FINGERPRINT`, `MANIFEST_SIGNING_CERTIFICATE`, and `SIGNING_CERTIFICATE_CHAIN`;
5. SBOM-enabled marker when enabled.

The ELF portion MUST NOT add a separate enabled/disabled marker or signing-mode tag. It must mirror the existing non-anchor conditions and component labels. The implementation must preserve the existing digest argument ordering and avoid ambiguous unlabelled additions.

## Compatibility rules

- Same complete inputs MUST produce the same digest.
- A different build cache version MUST prevent reuse.
- A different included stable ELF signing identity MUST prevent reuse when the corresponding existing signing condition is active.
- Merely encoding the fact that signing is enabled or disabled is not part of this contract.
- Secret key material and passphrases MUST NOT be included.
- Non-anchor digest ordering and inputs remain unchanged unless a test demonstrates an existing contract violation.
- No public command syntax or external API changes are required.
