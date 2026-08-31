# Data Model: ELF Signing Anchor Digest

This feature adds no persisted entities or schema. It changes the input model for an existing derived cache identity.

## Anchor digest input set

| Input | Source | Condition | Secret? | Contract label |
|---|---|---|---|---|
| Target platform | `calculateDigestOptions.TargetPlatform` | Existing anchor behavior | No | Positional anchor input |
| Holistic stage inputs | `calculateDigestOptions.HolisticInputs` | Existing anchor behavior; empty values omitted | No | Positional anchor inputs |
| BSign key fingerprint | `ELFSigningOptions.PGPPrivateKeyFingerprint` | `ELFSigningOptions.Enabled()` and `BsignEnabled` | No | `ELF_SIGNING_PGP_KEY_FINGERPRINT` |
| In-house signing certificate | `ManifestSigningOptions.Signer().Cert()` | `ELFSigningOptions.Enabled()` and `InHouseEnabled` | No | `MANIFEST_SIGNING_CERTIFICATE` |
| In-house certificate chain | `ManifestSigningOptions.Signer().Chain()` | `ELFSigningOptions.Enabled()` and `InHouseEnabled` | No | `SIGNING_CERTIFICATE_CHAIN` |
| SBOM marker | Existing conveyor state | SBOM enabled | No | Existing `sbom_enabled` marker |

The exact conditional values and labels for the three signing inputs are authoritative in the existing non-anchor checksum branch and must remain identical in the anchor branch.

## Excluded inputs

- `ELFSigningOptions.PGPPrivateKeyPassphrase`
- Private key bytes or files
- Any other secret signing material
- A standalone marker for signing being enabled, disabled, or absent

## Relationships and reuse semantics

- An **anchor result** is identified by the anchor digest.
- The digest is used by stage storage lookup for both primary/local and secondary/remote cache sources.
- Changing any applicable signing identity changes the anchor digest and selects a different cache identity.
- Keeping all applicable inputs unchanged preserves the existing digest and cache reuse behavior.
- The `sign` stage separately accounts for its manifest certificate and chain in its stage dependencies; the anchor additions must reflect the same contract without adding a second inconsistent representation.

## State transitions

No mutable entity state machine is introduced. The relevant derived identity transition is:

`same applicable inputs -> same anchor digest -> eligible for existing cache lookup`

`changed applicable signing identity -> different anchor digest -> prior identity is not selected`
