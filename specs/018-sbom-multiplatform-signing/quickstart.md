# Quickstart: Validating Multi-Platform SBOM Signing

**Feature**: 018-sbom-multiplatform-signing

Contracts: [build-signing.md](contracts/build-signing.md), [attest-verify-cli.md](contracts/attest-verify-cli.md). Result semantics: [data-model.md](data-model.md).

## Prerequisites

- Linux with Docker, kind, and a test registry — already provisioned (`task test:setup:environment` has been run; see constitution Environment Configuration).
- Foreign-arch pulls work (QEMU/binfmt — exercised by the existing `multiplatform` e2e label).
- Signing keys: reuse the e2e helper key material (`generateSigningKeyPairWithCert`, backed by `test/pkg/signutils` / delivery-kit-sdk certs) or `playground/signing/gen-keys.sh`.
- Optional: cosign ≥ v2.5.x binary for the stock-cosign check (SC-002).

## Quality gates (run in order; format first — it mutates files)

```sh
task format
task build
task lint
task test:unit
```

Scoped iteration: `task test:unit paths="./pkg/attestation/..."`, `task lint:golangci-lint golangciPaths="./pkg/build/..."`.

## Unit-level validation

```sh
task test:unit paths="./pkg/attestation/..."   # verify-all classification (missing/unsigned/invalid/verified)
task test:unit paths="./pkg/build/..."         # golden checksum tests stay byte-identical (FR-008)
task test:unit paths="./pkg/oci/..."           # platform resolution untouched
```

## E2E validation (the feature's SC-001/SC-003/SC-004/SC-005)

```sh
# New combined scenario + both parent suites:
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom && (sbom-signing || multiplatform)"
```

Expected outcomes (asserted by the suites):

1. **Signed MP build** (US1): two-platform build with `WERF_SIGN_KEY`/`WERF_SIGN_CERT` → each platform manifest digest carries exactly one Sigstore Bundle with signed DSSE and subject = that digest; no warning `multi-platform SBOM signing is not yet supported`; nothing attached to the index digest.
2. **verify-all** (US2): `werf attest verify --repo <repo> --type cyclonedx --key <pub.pem> --tag <index-tag>` without `--platform` → exit 0, table with both platforms `verified`. After deleting one platform's artifact → non-zero exit, that platform classified `missing`. With a wrong key → both platforms `invalid`.
3. **Regression** (US3): single-platform signed/unsigned suites and unsigned multiplatform suite pass unmodified; `attest get`/`sbom get` on index refs still demand `--platform`.
4. **Cache** (US4): unchanged signed rebuild logs "Use previously generated SBOM from registry" for both platforms; enabling the key on a previously unsigned project regenerates and supersedes both bare-DSSE artifacts.

## Manual stock-cosign check (SC-002, once per feature)

```sh
werf build --repo $REPO   # with WERF_SIGN_KEY/WERF_SIGN_CERT, platform: [linux/amd64, linux/arm64]

for p in linux/amd64 linux/arm64; do
  cosign verify-attestation --new-bundle-format \
    --insecure-ignore-tlog=true --key pub.pem --type cyclonedx \
    --platform "$p" "$REPO:<index-tag>"
done
# Expected: "The signatures were verified against the specified public key" for each platform.
# With a different public key: verification must fail for each platform.
```

## Command smoke test (unit suite cannot catch wiring SIGSEGVs)

```sh
./bin/werf attest verify --repo <repo> --type cyclonedx --key pub.pem --tag <index-tag>
```

Run once against the test registry before handing over (AGENTS.md: a green unit suite does not prove a command runs).
