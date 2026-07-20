# Quickstart: Hide OCI Attestation CLI Commands

**Phase**: 1 — Design & Contracts
**Date**: 2026-07-20
**Spec**: [spec.md](spec.md)

## Validation Scenarios

### Prerequisites

- Go 1.24.10+
- Working Go toolchain
- Build the binary: `task build`

### Scenario 1 — Commands Hidden from Help Output

```bash
# 1. Build the binary
task build

# 2. Verify attest command is NOT in top-level help
./bin/werf --help | grep -w attest
# Expected: no output (attest should not appear)

# 3. Run attest help directly
./bin/werf attest --help
# Expected: help text is shown (command still functional)

# 4. Verify subcommands are NOT listed in attest help
./bin/werf attest --help | grep -E '^\s+(sign|get|verify|ls)\s'
# Expected: no output (subcommands should not appear)
```

### Scenario 2 — Commands Still Functional When Invoked Explicitly

```bash
# Each command must still respond to --help when invoked directly
./bin/werf attest sign --help   # Expected: shows sign help
./bin/werf attest get --help    # Expected: shows get help
./bin/werf attest verify --help # Expected: shows verify help
./bin/werf attest ls --help     # Expected: shows ls help
```

### Scenario 3 — No Regression in Related Commands

```bash
# Other commands should still work normally
./bin/werf --help | grep sbom
# Expected: sbom is still visible

./bin/werf sbom --help
# Expected: sbom subcommands (get, merge, validate) are visible
```

### Scenario 4 — Unit Tests Pass

```bash
# Run unit tests for attestation and root packages
task test:unit -- -run 'TestAttest|TestRoot' ./cmd/werf/attest/... ./cmd/werf/root/...
# Expected: all tests pass without modification
```

## Success Criteria Reference

| Criterion | Verification |
|-----------|-------------|
| SC-001: `werf attest` not shown in `werf --help` | Scenario 1, step 2 |
| SC-002: `werf attest` not shown in `werf --help` | Scenario 1, step 2 |
| SC-003: Commands invokeable by name | Scenario 2 |
| SC-004: Tests pass unmodified | Scenario 4 |
| SC-005: No business logic changes | Code review |
| SC-006: Unhide = one-line change | Code review |

## Edge Cases to Verify

- Run `werf attest --help` — should show help but no subcommands listed
- Run `werf attest sign --help` — should show sign's help text
- Tab-complete `werf` and verify `attest` does not appear in suggestions
- Tab-complete `werf attest` and verify no subcommands appear in suggestions