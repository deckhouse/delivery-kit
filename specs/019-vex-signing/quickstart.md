# Quickstart: Validating VEX Signing

**Feature**: 019-vex-signing | Contracts: [build-vex-signing.md](contracts/build-vex-signing.md), [attest-openvex-cli.md](contracts/attest-openvex-cli.md), [artifact-slot-discrimination.md](contracts/artifact-slot-discrimination.md)

## Prerequisites

- Linux with Docker and a test registry (pre-configured e2e environment; on macOS only `task build`, `task lint`, `task test:unit` run).
- Signing key material: sigstore-encrypted PEM key + cert (see `playground/signing/gen-keys.sh` from 016), or the e2e helper `generateSigningKeyPairWithCert`.
- Optional: cosign ≥ v2.5.x binary for the stock-interop check.

## Quality gates (every change)

```sh
task format
task build
task deps:install:golangci-lint   # once per session
task lint
task test:unit
task doc:gen                      # after the --platform help-text change
```

## Unit validation

```sh
task test:unit paths="./pkg/oci/artifact/..."    # slot-key discrimination, legacy candidates
task test:unit paths="./pkg/attestation/..."     # openvex alias resolution, unsigned classification
task test:unit paths="./pkg/build/..."           # checksum composition, VexSigningOptions plumbing
```

## E2E validation

```sh
# VEX lifecycle including new signing scenarios
task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"

# SBOM+VEX coexistence and SBOM regression
task test:e2e paths="./test/e2e/sbom/..." labelFilter="sbom-signing"

# Legacy integration pass
task test:integration
```

Expected e2e assertions (mapped to spec):

1. **US1**: signed build → exactly one Bundle artifact at the image (index) digest, predicate `https://openvex.dev/ns`, `dev.sigstore.bundle.predicateType` annotation present, in-process DSSE verification passes with the right key and fails with a wrong one.
2. **US2**: SBOM+VEX build (no key and with key) → both artifacts listed by `attest ls`; changing only the VEX file republishes only VEX.
3. **US3**: keyless build byte-form matches the legacy artifact form (bare DSSE, versioned predicate).
4. **US4**: rebuild unchanged → "VEX artifact is up to date" log; add/rotate key → republish observed.
5. **US5**: `attest verify --type openvex` succeeds on manifest and index refs; unsigned artifact yields the "present but unsigned" classification; `--platform` + index ref + openvex → usage error.

## Manual stock-cosign check (once, SC-002)

```sh
werf build --repo "$REPO" --sign-key key.pem --sign-cert cert.pem   # project with vex + platform: [linux/amd64, linux/arm64]

cosign verify-attestation --new-bundle-format \
  --key pub.pem --insecure-ignore-tlog=true \
  --type openvex "$REPO@<index-digest>"        # → "The signatures were verified against the specified public key"

cosign verify-attestation ... --key wrong-pub.pem ...   # → must fail
```

## Success criteria mapping

| SC | Validation |
|---|---|
| SC-001 | e2e US1 (single- and multi-platform) |
| SC-002 | manual cosign check above + in-process DSSE verification in e2e |
| SC-003 | e2e US2 coexistence suite |
| SC-004 | existing VEX lifecycle e2e unmodified + legacy-artifact read test |
| SC-005 | e2e US4 cache assertions |
| SC-006 | quality gates + labeled e2e suites on Linux CI |
