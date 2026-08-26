# SC-002 Verification Record: Stock Cosign Offline Multi-Platform Verify

**Date**: 2026-08-19 | **Host**: macOS arm64 (Docker Desktop, linux containers) | **Cosign**: v3.0.6 (Homebrew)

## Procedure

The `sbom-signing && multiplatform && simple` e2e suite was executed with a real cosign binary injected:

```sh
WERF_TEST_K8S_DOCKER_REGISTRY=localhost:5100 \
WERF_TEST_COSIGN_BIN=/opt/homebrew/bin/cosign \
WERF_EXPERIMENTAL_STAPEL_ARM=1 (set by the suite) \
task test:e2e paths="./test/e2e/sbom" labelFilter="sbom-signing && multiplatform && simple"
```

For each of the two platforms (`linux/amd64`, `linux/arm64`) of the werf-built, key-signed
multi-platform image, `runCosignOfflineVerify` executed against the platform manifest digest:

```sh
cosign trusted-root create --out tr.json
cosign verify-attestation --new-bundle-format --trusted-root tr.json \
  --insecure-ignore-tlog=true --key pub.pem --type cyclonedx <repo>@<platform-digest>
```

## Result

- SUCCESS: 3 specs passed (vanilla-docker entry, buildkit-docker entry, unsigned→supersede scenario);
  cosign printed "verified" for both platform attestations in both signed entries (4 verifications total).
- Wrong-key rejection was proven in the same run in-process (DSSE verify + `attest verify` verify-all
  classified both platforms `invalid` with a foreign public key).

## Notes

- Ed25519 key material, sigstore-encrypted PEM, empty passphrase (e2e helper `generateSigningKeyPairWithCert`).
- CI does not install cosign; there the same assertions run in-process and the cosign step self-skips.
