# Contract: `attest` CLI for OpenVEX attestations

**Feature**: 019-vex-signing

## `attest verify --type openvex`

| Reference resolves to | `--platform` | Behavior |
|---|---|---|
| image manifest | absent | verify VEX attestation at that digest (unchanged resolution) |
| image manifest | set | existing platform validation applies (unchanged) |
| image index | absent | verify VEX attestation attached to the **index digest** itself — no platform expansion, no `ErrIndexPlatformRequired` |
| image index | set | usage error: OpenVEX attestations are image-level; `--platform` is not applicable |

Verification outcome classification:

| State | Exit | Message class |
|---|---|---|
| signed bundle, a `--key` matches | 0 | predicate printed to stdout |
| signed bundle, no key matches | ≠0 | DSSE signature verification failure |
| bare-DSSE artifact (unsigned) | ≠0 | "present but unsigned (legacy format)" — advise rebuild with `--sign-key` |
| no VEX artifact | ≠0 | not-found (existing wording) |

Predicate matching accepts the alias set {`https://openvex.dev/ns`, `https://openvex.dev/ns/v0.2.0`} for `--type openvex` and for either full URI.

## `attest get --type openvex`

Same reference-resolution rules as `verify` (index digest used as-is, `--platform` rejected on index refs); prints the OpenVEX predicate of signed or unsigned artifacts (dual-format read: bundle first, bare-DSSE fallback).

## `attest ls`

Unchanged interface. Both SBOM and VEX entries of a digest are listed with their predicate types and signed flags; on an index reference the existing per-platform behavior applies for platform digests, and VEX entries appear when the index digest itself is listed.

## Non-goals

`attest sign` is not extended to VEX. `sbom get`/`sbom merge` semantics unchanged (they must merely keep working next to VEX entries — coexistence contract).

## CLI help text

The `--platform` help of `attest verify`/`attest get` gains the openvex caveat → `task doc:gen` required.

## Stock cosign interoperability

`cosign verify-attestation --new-bundle-format --key <pub.pem> --insecure-ignore-tlog=true --type openvex <ref>` succeeds offline against the published signed artifact (single-platform ref and multi-platform index ref alike); a wrong key fails.
