# Feature Specification: Hide OCI Attestation CLI Commands

**Feature Branch**: `feat/hide-oci-attest-commands`

**Created**: 2026-07-20

**Status**: Draft

**Input**: User description: "Скрыть команды attest из спецификации 003-oci-attestation-commands от пользователей (hidden). В будущем планируется использовать механизм werf.yaml для этих целей. Если его окажется не достаточно, возможно, потребуется часть из этих команд."

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. Key subsystems:

- **Build** (`pkg/build/`) — Container image building via Buildah
- **Deploy** (`pkg/deploy/`) — Kubernetes deployment via werf/nelm (Helm-based)
- **SBOM** (`pkg/sbom/`) — Software Bill of Materials generation and validation
- **Cleanup** (`pkg/cleaning/`) — Container registry cleanup policies
- **Attestation** (`pkg/attestation/`) — In-toto attestation signing, verification, retrieval, and listing
- **OCI Artifact** (`pkg/oci/artifact/`) — OCI artifact attachment and fallback index management
- **Docker Registry** (`pkg/docker_registry/`) — OCI registry operations
- **Config** (`pkg/config/`) — werf.yaml configuration parsing

### Background

The [003-oci-attestation-commands](../003-oci-attestation-commands/spec.md) specification introduced four `werf attest *` CLI commands: `sign`, `get`, `verify`, and `ls`. These commands expose attestation operations directly via the CLI. However, the long-term vision is to manage attestation workflows through `werf.yaml` configuration rather than dedicated CLI commands. To avoid committing to a CLI surface that may be replaced or significantly redesigned, these commands should be hidden from users while remaining functional for internal and experimental use.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Hide Attestation Commands from CLI (Priority: P1)

A user running `werf --help`, `werf attest --help`, or pressing Tab for auto-completion should not see the attestation subcommands (`sign`, `get`, `verify`, `ls`). These commands must be marked as hidden in the Cobra command tree. If a user explicitly knows the command exists and types it in full, the command should still execute normally.

**Why this priority**: This is the primary goal — removing the commands from user discovery. All four commands must be hidden consistently.

**Independent Test**: Run `werf attest --help` and verify that `sign`, `get`, `verify`, and `ls` do not appear in the output. Then run `werf attest sign --help` explicitly and verify the command is still functional.

**Acceptance Scenarios**:

1. **Given** a user runs `werf attest --help`, **When** they inspect the available subcommands, **Then** `sign`, `get`, `verify`, and `ls` MUST NOT appear in the list
2. **Given** a user runs `werf attest sign --help`, **When** they explicitly invoke the command with `--help`, **Then** the command MUST execute and show its help text (hidden commands still respond to explicit invocation)
3. **Given** a user runs `werf attest get --type openvex --repo <repo> --digest <digest>`, **When** they explicitly invoke the full command, **Then** the command MUST execute and return the attestation predicate as before
4. **Given** a user runs `werf attest verify --type openvex --key <key> --repo <repo> --digest <digest>`, **When** they explicitly invoke the full command, **Then** the command MUST execute and verify the signature as before
5. **Given** a user runs `werf attest ls --repo <repo> --digest <digest>`, **When** they explicitly invoke the full command, **Then** the command MUST execute and list attestations as before

---

### User Story 2 — Preserve Command Functionality (Priority: P2)

Existing scripts, CI pipelines, or internal tools that invoke `werf attest *` commands directly by name must continue to work. Hiding a command in Cobra only removes it from help output and auto-completion — it does not remove the command handler.

**Why this priority**: Backward compatibility for any existing consumers of these commands. While these commands are not yet widely advertised, internal or experimental usage should not break.

**Independent Test**:  Execute each of the four `werf attest *` commands with valid arguments and verify they produce the same output as before the hiding change.

**Acceptance Scenarios**:

1. **Given** a script runs `werf attest sign --predicate <file> --type openvex --sign-key <key> --repo <repo> --digest <digest>`, **When** the command is hidden, **Then** the script MUST succeed and produce the same attestation artifact
2. **Given** a CI pipeline calls `werf attest get --type openvex --repo <repo> --digest <digest>`, **When** the command is hidden, **Then** the pipeline MUST succeed and receive the expected predicate output

---

### User Story 3 — Future: Werf.yaml Configuration (Priority: P3)

In a future iteration, attestation workflows should be configured via `werf.yaml` instead of CLI commands. This specification does not implement that mechanism — it only prepares the ground by hiding the CLI surface to reduce user expectations and allow the configuration design to proceed without backward compatibility concerns.

**Why this priority**: This is a forward-looking requirement. The hiding change is a prerequisite for the future redesign.

**Independent Test**: This is a design goal, not a testable change in this iteration. Verification happens when the werf.yaml attestation configuration feature is implemented.

**Acceptance Scenarios**:

1. **Given** a future `werf.yaml` attestation configuration feature exists, **When** a user configures attestation in `werf.yaml`, **Then** they should not need to use `werf attest *` commands
2. **Given** the `werf.yaml` mechanism is insufficient for a specific use case, **When** the team decides to expose a command, **Then** only the required command is unhidden (not all four)

### Edge Cases

- What happens if a user discovers a hidden command through other means (e.g., reading the source code)? — The command works normally; hiding is soft removal from help/autocomplete only
- What happens to `werf attest --help` output when all subcommands are hidden? — Cobra will show an empty command group or a "no available commands" message; this is acceptable since the parent `attest` command itself should also be hidden once its subcommands are all hidden
- Should the parent `werf attest` command itself be hidden? — Yes, once all its subcommands are hidden, the parent should also be hidden so it does not appear in `werf --help`

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The `werf attest sign` Cobra command MUST be marked as hidden (`Hidden: true`)
- **FR-002**: The `werf attest get` Cobra command MUST be marked as hidden (`Hidden: true`)
- **FR-003**: The `werf attest verify` Cobra command MUST be marked as hidden (`Hidden: true`)
- **FR-004**: The `werf attest ls` Cobra command MUST be marked as hidden (`Hidden: true`)
- **FR-005**: The parent `werf attest` command MUST be marked as hidden (`Hidden: true`)
- **FR-006**: All hidden commands MUST remain fully functional — hiding MUST NOT affect command execution, argument parsing, or output
- **FR-007**: Hiding a command MUST be limited to setting `Hidden: true` on the Cobra `Command` struct — no other code changes to the command handlers or business logic are permitted
- **FR-008**: Unit tests for the hidden commands MUST continue to pass without modification

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- Add `var _ Interface = (*Impl)(nil)` compile-time check for each interface implementation

### Key Entities

- **Cobra Command**: The `cobra.Command` struct with a `Hidden` field. Setting `Hidden: true` removes the command from help output and auto-completion but does not disable it.
- **Attestation Subcommands**: `sign`, `get`, `verify`, `ls` — four subcommands under the `werf attest` parent command, defined in `cmd/werf/attest/` or similar CLI command tree location.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Running `werf attest --help` does not show `sign`, `get`, `verify`, or `ls` in the available subcommands list
- **SC-002**: Running `werf --help` does not show the `attest` command in the top-level command list
- **SC-003**: All four `werf attest *` commands can still be invoked by name and produce identical output to their non-hidden state
- **SC-004**: All existing unit tests for the attestation commands pass without modification
- **SC-005**: The change is purely declarative (setting `Hidden: true`) — no business logic, imports, or function signatures are altered
- **SC-006**: Future unhiding of any single command is a one-line change (setting `Hidden: false`)

## Assumptions

- The attestation commands are defined as Cobra `Command` structs in the `cmd/werf/` package tree
- The `Hidden` field is already available on the `cobra.Command` struct (standard Cobra functionality)
- No existing documentation, tutorials, or public references need updating because these commands were already experimental/unannounced
- The `werf attest` parent command itself should also be hidden to avoid showing an empty command group in help output
- The future `werf.yaml` attestation configuration design is out of scope for this specification
