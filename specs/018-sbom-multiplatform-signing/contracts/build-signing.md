# Contract: `werf build` — multi-platform SBOM signing

**Feature**: 018-sbom-multiplatform-signing

## Inputs (unchanged flags)

- `--sign-key` / `WERF_SIGN_KEY` — sigstore-encrypted PEM private key. Presence enables SBOM signing (no separate toggle).
- `--sign-cert` / `WERF_SIGN_CERT` — public signing certificate. Required whenever `--sign-key` is set (existing gate: "signing certificate is required...").
- `platform: [...]` in `werf.yaml` / `--platform` — multi-platform build definition (unchanged).

## Behavior

| Scenario | Before (main) | After |
|---|---|---|
| Multi-platform build, key set | per-platform **unsigned** bare-DSSE + warning `multi-platform SBOM signing is not yet supported, SBOM will be unsigned` | per-platform **signed** Sigstore Bundle v0.3; no warning |
| Multi-platform build, no key | per-platform unsigned bare-DSSE | identical (byte-form) |
| Single-platform build (key or no key) | 016 behavior | identical (byte-form, checksum, cache) |
| Key set, cert missing | build fails | identical |
| Signer yields zero signatures for any platform | n/a (guard) | build fails fail-fast, error names image and platform; remaining platform SBOMs of that image are not converged |

## Published artifact (per platform, key set)

Identical in form to the 016 single-platform signed artifact:

- attached to the fallback tag `sha256-<hex>` of the **platform manifest digest**;
- artifactType `application/vnd.dev.sigstore.bundle.v0.3+json`;
- in-toto `subject` digest = platform manifest digest;
- annotations: `io.werf.checksum` (includes signer fingerprint + platform), `io.werf.image-name`, `io.werf.target-platform` (the actually scanned platform);
- DSSE envelope with non-empty `signatures`; predicateType `https://cyclonedx.org/bom`;
- stale bare-DSSE entry for the same image name in that fallback index is superseded;
- **nothing** is attached to the index digest.

## Cache contract

- Unchanged rebuild with the same key: cache hit per platform ("Use previously generated SBOM from registry"), no re-publish.
- Enabling signing / rotating the key: checksum changes for every platform → regenerate + re-sign all platforms.
- Unsigned multi-platform and all single-platform checksums are byte-identical to main (golden tests must pass unmodified).
