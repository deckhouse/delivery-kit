# Research: Hide OCI Attestation CLI Commands

**Phase**: 0 — Outline & Research
**Date**: 2026-07-20
**Spec**: [spec.md](spec.md)

## Overview

This research phase analyzes all unknowns and decisions needed to implement the hiding of `werf attest *` CLI commands.

## Unknowns Resolution

All aspects of this feature were known upfront. No [NEEDS CLARIFICATION] markers exist in the spec.

## Technology Choices

### Hiding Mechanism: Cobra `Hidden` field

- **Decision**: Use `cobra.Command.Hidden = true` on each command
- **Rationale**: This is the standard, officially documented Cobra mechanism for hiding commands from help output and shell auto-completion. It preserves full command functionality — only the help/autocomplete surface is affected.
- **Alternatives considered**:
  - Removing commands entirely — rejected because future `werf.yaml` mechanism may need partial or full restoration
  - Re-registering under a different command tree — unnecessary complexity; `Hidden` achieves the same effect with a single boolean
  - Using build tags — would prevent running hidden commands even when explicitly invoked, violating FR-006

### Precedent in Codebase

The `stageCmd` function in `cmd/werf/root/root.go` (line 258) already uses `Hidden: true`:

```go
func stageCmd(ctx context.Context) *cobra.Command {
    cmd := common.SetCommandContext(ctx, &cobra.Command{
        Use:    "stage",
        Hidden: true,
    })
    cmd.AddCommand(
        stage_image.NewCmd(ctx),
    )
    return cmd
}
```

This confirms the pattern is established and well-tested in this project.

## Commands to Hide

| # | Command | Location | Current State |
|---|---------|----------|--------------|
| 1 | `werf attest` (parent) | `cmd/werf/root/root.go:215-228` | Not hidden |
| 2 | `werf attest sign` | `cmd/werf/attest/sign/sign.go` | Not hidden |
| 3 | `werf attest get` | `cmd/werf/attest/get/get.go` | Not hidden |
| 4 | `werf attest verify` | `cmd/werf/attest/verify/verify.go` | Not hidden |
| 5 | `werf attest ls` | `cmd/werf/attest/ls/ls.go` | Not hidden |

## Conclusions

No further research needed. The implementation is straightforward: add `Hidden: true` to the `cobra.Command` struct literal in each of the 5 locations above.