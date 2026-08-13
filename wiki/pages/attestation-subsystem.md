---
title: Attestation Subsystem (pkg/attestation/)
type: concept
sources: [S008, S020]
updated: 2026-08-10
---

The `pkg/attestation/` library provides in-toto attestation signing, verification, retrieval, and listing for OCI images. It is used by the `werf attest` CLI commands and was refactored from the earlier SBOM-specific `pkg/sbom/image/dsse.go` to serve as a shared library (S008).

## DSSE envelopes

Attestations are wrapped in DSSE (Dead Simple Signing Envelope) format (`application/vnd.dsse.envelope.v1+json`). The envelope is a JSON structure with a base64-encoded `payload`, a `payloadType`, and a `signatures` array. The library uses `go-securesystemslib` for envelope types and `sigstore/sigstore` for signature/verification primitives (S008).

## In-toto statements

The payload inside the DSSE envelope is an in-toto Statement v1 (`https://in-toto.io/Statement/v1`). The statement includes a `subject` array referencing the parent image (name + digest), a `predicateType` URI, and the user-supplied `predicate` payload (e.g., an OpenVEX vulnerability report) (S008).

## Predicate type resolution

Predicate types can be specified via short names or full URIs:

| Short name | Full URI |
|------------|----------|
| `openvex` | `https://openvex.dev/ns/v0.2.0` |
| `slsaprovenance` | `https://slsa.dev/provenance/v0.2` |
| `slsaprovenance1` | `https://slsa.dev/provenance/v1` |
| `spdxjson` | `https://spdx.dev/Document` |
| `cyclonedx` | `https://cyclonedx.org/bom` |

Any URI containing `://` is passed through directly. Unknown short names are rejected (S008).

## Key loading

Signing keys can be loaded from:
- PEM-encoded private keys (PKCS#8, EC, RSA, Ed25519).
- HashiCorp Vault references via `hashivault://` scheme (using `deckhouse/delivery-kit-sdk`).

Verification keys are PEM-encoded public keys in any algorithm supported by `sigstore/sigstore` (S008).

## CAS retry for concurrent writes

The `Attach` function uses compare-and-swap (CAS) with up to 3 retries and exponential backoff to detect concurrent writes to the fallback index. This prevents data loss when multiple processes attach attestations to the same image simultaneously (S008).

## Index platform resolution

For multi-platform images, `pkg/oci/artifact/platform.go` provides index resolution helpers (S020):

- **`ResolvePlatformDigest`**: resolves an index + platform to a platform manifest digest; an index reference without `--platform` returns `ErrIndexPlatformRequired` listing the available platforms and their digests (S020).
- **`ListIndexPlatforms`**: enumerates the platforms in an image index (S020).
- **`NormalizePlatform`**: normalizes platform input (e.g. `linux/arm64/v8` → `linux/arm64`) for consistent matching (S020).
- **`PlatformMatches`**: matches a platform against a manifest config platform, with variant matching restricted to `os/arch` requests (S020).

These helpers are used by `werf attest get`, `attest verify`, `attest ls`, and `werf sbom get` to resolve `--platform` flags (S020).

## SBOM refactoring

The existing `pkg/sbom/image/dsse.go` was refactored to delegate to `pkg/attestation/` to avoid code duplication. The attestation library is the single source of truth for DSSE and in-toto operations (S008).

See also: [Fallback index mechanism](./fallback-index-mechanism.md), [werf attest commands](./werf-attest-commands.md), [Per-platform SBOM](./per-platform-sbom.md).