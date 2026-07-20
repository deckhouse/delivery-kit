# Data Model: Hide OCI Attestation CLI Commands

**Phase**: 1 — Design & Contracts
**Date**: 2026-07-20
**Spec**: [spec.md](spec.md)

## Entity: Cobra Command Tree

This feature operates on the existing Cobra command tree in `cmd/werf/`. The only attribute modified is the `Hidden` boolean on each command struct.

### Command Tree Structure

```
werf (rootCmd)
 └── attest (parent, cmd/werf/root/root.go:215-228)
      ├── sign   (attest_sign.NewCmd,   cmd/werf/attest/sign/sign.go)
      ├── get    (attest_get.NewCmd,    cmd/werf/attest/get/get.go)
      ├── verify (attest_verify.NewCmd, cmd/werf/attest/verify/verify.go)
      └── ls     (attest_ls.NewCmd,     cmd/werf/attest/ls/ls.go)
```

### Modified Field

| Field | Type | Current Value | New Value | Location |
|-------|------|--------------|-----------|----------|
| `cmd.Hidden` | `bool` | `false` (default, not set) | `true` | Parent command: `attestCmd()` in `root.go` |
| `cmd.Hidden` | `bool` | `false` (default, not set) | `true` | Subcommand constructors: `sign.go`, `get.go`, `verify.go`, `ls.go` |

### State Transitions

This is a static boolean change — no runtime state transitions. The command is either hidden or visible at compile time.