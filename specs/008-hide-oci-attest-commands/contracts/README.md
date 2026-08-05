# CLI Contracts: Hide OCI Attestation Commands

**Date**: 2026-07-20 | **Status**: Updated

## Overview

This feature does **NOT** modify any CLI contracts (flags, arguments, output formats, error behavior). Hiding is a presentation-only change that affects `--help` output and auto-completion only.

## Visibility Change

| Command | Before | After |
|---------|--------|-------|
| `werf attest` | Visible in `werf --help` | Hidden from `werf --help` |
| `werf attest sign` | Visible in `werf attest --help` | Hidden from `werf attest --help` |
| `werf attest get` | Visible in `werf attest --help` | Hidden from `werf attest --help` |
| `werf attest verify` | Visible in `werf attest --help` | Hidden from `werf attest --help` |
| `werf attest ls` | Visible in `werf attest --help` | Hidden from `werf attest --help` |

**Invocation guarantees**: All commands remain invocable by exact name. All flags, arguments, and behavior are unchanged. Shell auto-completion will not suggest these commands.

**Unhiding contract**: Any single command can be unhidden by setting `Hidden: false` (or removing the `Hidden: true` line) on its `cobra.Command` struct — a one-line change.

**Backward compatibility**: No breaking changes. Scripts and CI pipelines that invoke these commands by full name continue to work. No deprecation notices needed.

## Contract Status

| Command | Contract | Change |
|---------|----------|--------|
| `werf attest sign` | [Sign contract](../../../cmd/werf/attest/sign/sign.go) | No change — `--predicate`, `--type`, `--digest`/`--tag`, `--sign-key`, `--image` flags unchanged |
| `werf attest get` | [Get contract](../../../cmd/werf/attest/get/get.go) | No change — `--type`, `--digest`/`--tag`, `--image` flags unchanged |
| `werf attest verify` | [Verify contract](../../../cmd/werf/attest/verify/verify.go) | No change — `--type`, `--key`, `--digest`/`--tag`, `--image` flags unchanged |
| `werf attest ls` | [Ls contract](../../../cmd/werf/attest/ls/ls.go) | No change — `--digest`/`--tag` flags unchanged |

## Flag Reference (unchanged)

### `werf attest sign`

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--predicate` | | `string` | yes | Path to the predicate file |
| `--type` | | `string` | yes | Predicate type (short name or full URI) |
| `--digest` | | `string` | mutual | Digest of the parent image |
| `--tag` | | `string` | mutual | Tag of the parent image |
| `--image` | | `string` | no | Image name for artifact indexing |
| `--repo` | | `string` | yes | Container registry address |
| `--sign-key` | | `string` | yes | Signing key reference |

### `werf attest get`

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--type` | | `string` | yes | Predicate type |
| `--digest` | | `string` | mutual | Digest of the image |
| `--tag` | | `string` | mutual | Tag of the image |
| `--image` | | `string` | no | Image name for artifact lookup |
| `--repo` | | `string` | yes | Container registry address |

### `werf attest verify`

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--type` | | `string` | yes | Predicate type |
| `--key` | | `[]string` | yes | Public key PEM file path(s) |
| `--digest` | | `string` | mutual | Digest of the image |
| `--tag` | | `string` | mutual | Tag of the image |
| `--image` | | `string` | no | Image name for artifact lookup |
| `--repo` | | `string` | yes | Container registry address |

### `werf attest ls`

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--digest` | | `string` | mutual | Digest of the image |
| `--tag` | | `string` | mutual | Tag of the image |
| `--repo` | | `string` | yes | Container registry address |

## Output Formats (unchanged)

- `werf attest get`: predicate content to stdout
- `werf attest verify`: predicate content to stdout
- `werf attest ls`: table with columns PREDICATE TYPE, DIGEST, SIGNED (tab-separated)
- `werf attest sign`: no output on success, errors to stderr

## Error Behavior (unchanged)

All existing error messages and exit codes remain the same. Hiding does not affect error handling.