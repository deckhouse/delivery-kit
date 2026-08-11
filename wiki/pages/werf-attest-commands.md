---
title: werf attest Commands
type: reference
sources: [S008, S009, S020]
updated: 2026-08-10
---

Four CLI commands under `werf attest` for managing in-toto attestations on OCI images: `sign`, `get`, `verify`, and `ls`. All commands accept `--repo` (required) and `--digest` or `--tag` (mutually exclusive) to identify the parent image (S008).

These commands are hidden from help output and shell auto-completion using Cobra's `Hidden: true` field (S009). The parent `werf attest` command is also hidden. They remain fully functional — only the help/autocomplete surface is affected. The commands are hidden (not removed) because a future `werf.yaml` mechanism may need partial or full restoration of the attestation CLI surface (S009). The `stageCmd` in `cmd/werf/root/root.go` established this pattern in the codebase prior to this feature (S009).

## Common flags

| Flag | Description |
|------|-------------|
| `--repo` | Container registry address (required) |
| `--digest` | Image digest (mutually exclusive with `--tag`) |
| `--tag` | Image tag, resolved to digest (mutually exclusive with `--digest`) |
| `--platform` | Target platform for multi-platform images (e.g. `linux/amd64`); an index reference without `--platform` errors listing available platforms |

## werf attest sign

Create a signed attestation and attach it to an image.

| Flag | Required | Description |
|------|----------|-------------|
| `--predicate` | Yes | Path to predicate file |
| `--type` | Yes | Predicate type (short name or URI) |
| `--sign-key` | Yes | Signing key (PEM file or `hashivault://` reference) |
| `--image` | Yes | Image name for artifact indexing |

The predicate is wrapped in an in-toto Statement v1, signed with a DSSE envelope, and attached as an OCI artifact to the parent image using the fallback index mechanism (S008).

## werf attest get

Retrieve an attestation's predicate from an image.

| Flag | Required | Description |
|------|----------|-------------|
| `--type` | Yes | Predicate type to retrieve |
| `--image` | No | Image name (optional; when omitted, returns first matching attestation) |

Outputs the predicate to stdout. Fails with `not found` if no matching attestation exists (S008).

For multi-platform images, `--platform` selects which platform's attestation to retrieve. An index reference without `--platform` fails with an error listing the available platforms and their digests (S020).

## werf attest verify

Verify a signed attestation and return the predicate.

| Flag | Required | Description |
|------|----------|-------------|
| `--type` | Yes | Predicate type to verify |
| `--key` | Yes (repeatable) | Verification public keys (any one must match) |
| `--image` | No | Image name (optional) |

Verification uses any-match semantics: if any provided key matches the signer, verification succeeds. `VerifyDSSE` returns the first matching signature payload (S008).

For multi-platform images, `--platform` selects which platform's attestation to verify. If the flag targets a single-platform manifest with a different platform, the command fails with a mismatch error (S020).

## werf attest ls

List attestations attached to an image.

| Flag | Required | Description |
|------|----------|-------------|
| — | — | No type or key flags |

Outputs a table with columns: PREDICATE TYPE, DIGEST, SIGNED, and PLATFORM. For an index reference, all platforms are expanded into one table with a PLATFORM column. Shows `-` for non-index images, `(unknown)` for unrecognized predicate type URIs, and `No attestations found` if none exist (S008). An optional `--platform` flag filters to the specified platform (S020).

See also: [Attestation subsystem](./attestation-subsystem.md), [Fallback index mechanism](./fallback-index-mechanism.md), [Per-platform SBOM](./per-platform-sbom.md).