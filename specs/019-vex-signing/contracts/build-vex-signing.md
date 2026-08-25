# Contract: `werf build` VEX signing behavior

**Feature**: 019-vex-signing

## Behavior matrix

| werf.yaml `vex` | `--sign-key`/`--sign-cert` | Platforms | Published VEX artifact | Attached to |
|---|---|---|---|---|
| absent | any | any | none (no VEX operations) | — |
| set | absent | single | bare DSSE, predicate `https://openvex.dev/ns/v0.2.0`, empty signatures | image manifest digest |
| set | absent | multi | same bare DSSE | image index digest |
| set | present | single | Sigstore Bundle v0.3, signed DSSE, predicate `https://openvex.dev/ns` | image manifest digest |
| set | present | multi | same signed bundle | image index digest |
| set | `--sign-key` without `--sign-cert` | any | build fails before VEX work (existing signing-gate error) | — |

## Artifact contract (signed)

- Bundle mediaType/artifactType: `application/vnd.dev.sigstore.bundle.v0.3+json`
- `verificationMaterial.publicKey.hint` = base64(SHA-256(DER SPKI of the public key)); no cert embedded
- in-toto subject: `{name: <repo>, digest: {sha256: <attached digest hex>}}`
- Zero-signature envelope from a configured signer → build error naming the image
- Descriptor+manifest annotations: `io.werf.checksum`, `io.werf.image-name`, `io.werf.target-platform` (when set), `dev.sigstore.bundle.predicateType`
- Publish supersedes the bare-DSSE VEX entry of the same image (and only it)

## Coexistence contract

Given SBOM and VEX both enabled for one image, after any build:

- both artifacts exist under the image's fallback tag(s); neither publish evicts the other
- rebuilding with only one input changed republishes only that artifact
- publish-needed cache checks of each kind only ever inspect entries of their own kind

## Failure contract

- Any VEX signing/publish failure fails the build with an error naming the image (`unable to converge VEX for image %q`)
- Reads of pre-feature artifacts (no predicate annotation) keep working; a read for one kind never returns the other kind
