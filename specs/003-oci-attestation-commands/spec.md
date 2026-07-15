# Feature Specification: OCI Attestation Commands

**Feature Branch**: `feat/oci/commands-to-manage-oci-artifacts`

**Created**: 2026-07-15

**Status**: Migrated

**Input**: Reverse-engineered from source code changes in branch `feat/oci/commands-to-manage-oci-artifacts` (3 commits on top of `origin/main`)

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

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Sign an Attestation for an Image (Priority: P1)

A user who has built a container image wants to attach a signed in-toto attestation (e.g., an OpenVEX vulnerability statement) to the image in the container registry. They provide a predicate file, a predicate type, a signing key, and identify the image by digest or tag. The system wraps the predicate in an in-toto Statement v1, signs it with a DSSE envelope, and attaches it as an OCI artifact to the parent image.

**Why this priority**: This is the core write operation — without signing, there is nothing to get, verify, or list. All other commands depend on attestations existing in the registry.

**Independent Test**: Can be fully tested by building an image with `werf build`, then calling `werf attest sign` with a test predicate file, a generated ECDSA key, and verifying the attestation is attached via `werf attest ls` or by inspecting the fallback index in the registry.

**Acceptance Scenarios**:

1. **Given** a user has an image in a container registry, **When** they run `werf attest sign --predicate <file> --type <type> --sign-key <key> --repo <repo> --digest <digest>`, **Then** the predicate is wrapped in an in-toto Statement v1, signed with a DSSE envelope, and attached to the image as an OCI artifact
2. **Given** the user specifies `--tag` instead of `--digest`, **When** the tag is resolved to a digest, **Then** the attestation is attached to the resolved digest
3. **Given** the user omits `--predicate`, **When** they run the command, **Then** the command fails with `--predicate is required`
4. **Given** the user omits `--type`, **When** they run the command, **Then** the command fails with `--type is required`
5. **Given** the user specifies both `--digest` and `--tag`, **When** they run the command, **Then** the command fails with `--digest and --tag are mutually exclusive`
6. **Given** the user specifies neither `--digest` nor `--tag`, **When** they run the command, **Then** the command fails requesting one of them
7. **Given** the user provides an unknown predicate type short name, **When** they run the command, **Then** the command fails with `unknown predicate type`

---

### User Story 2 — Get an Attestation from an Image (Priority: P2)

A user wants to retrieve the predicate content of a specific attestation attached to an image. They specify the predicate type and identify the image by digest or tag. The system pulls the DSSE envelope from the OCI artifact, unwraps the in-toto statement, and outputs the predicate to stdout.

**Why this priority**: This is the primary read operation — users need to inspect attestation content without verifying signatures. It is simpler than verify and serves as a prerequisite for automated attestation consumption.

**Independent Test**: Can be tested independently by signing an attestation to an image, then calling `werf attest get --type <type> --repo <repo> --digest <digest>` and verifying the output matches the original predicate.

**Acceptance Scenarios**:

1. **Given** an image has a signed attestation, **When** the user runs `werf attest get --type <type> --repo <repo> --digest <digest>`, **Then** the predicate content is printed to stdout
2. **Given** the attestation's predicate type does not match the requested type, **When** the user runs the command, **Then** the command fails with a type mismatch error
3. **Given** the image has no attestation attached, **When** the user runs the command, **Then** the command fails with `not found`
4. **Given** the user specifies `--tag` instead of `--digest`, **When** the tag is resolved to a digest, **Then** the attestation is retrieved from the resolved digest

---

### User Story 3 — Verify a Signed Attestation (Priority: P3)

A user wants to cryptographically verify that an attestation attached to an image was signed by a trusted key. They provide one or more public keys, the predicate type, and identify the image. The system pulls the DSSE envelope, verifies the signature against the provided keys, and outputs the predicate to stdout if verification succeeds.

**Why this priority**: Verification is a critical trust operation but depends on the attestation already existing (US1) and the user being able to inspect it (US2). It is the most complex operation and adds the most value for security-conscious users.

**Independent Test**: Can be tested by signing an attestation with key A, then verifying with key A (should succeed) and with key B (should fail). Can also test with multiple verifiers where any one matches.

**Acceptance Scenarios**:

1. **Given** an image has a signed attestation, **When** the user runs `werf attest verify --type <type> --key <pubkey> --repo <repo> --digest <digest>`, **Then** the signature is verified against the public key and the predicate is printed to stdout
2. **Given** the user provides multiple `--key` flags, **When** any one of the keys matches the signer, **Then** verification succeeds and the predicate is returned
3. **Given** the user provides a key that does not match the signer, **When** they run the command, **Then** verification fails with `signature verification failed`
4. **Given** the attestation is unsigned, **When** the user runs verify, **Then** the command fails with `no signatures`

---

### User Story 4 — List Attestations on an Image (Priority: P4)

A user wants to see all attestations attached to an image in a table format showing predicate type, digest, and whether the attestation is signed. They identify the image by digest or tag.

**Why this priority**: Listing is a discovery operation — it depends on attestations existing (US1) and is the least critical operation. It provides useful diagnostics but is not required for the core attestation workflow.

**Independent Test**: Can be tested by signing one or more attestations to an image, then calling `werf attest ls --repo <repo> --digest <digest>` and verifying the output lists the expected predicate types and signed status.

**Acceptance Scenarios**:

1. **Given** an image has attestations attached, **When** the user runs `werf attest ls --repo <repo> --digest <digest>`, **Then** a table is printed with columns PREDICATE TYPE, DIGEST, and SIGNED
2. **Given** the image has no attestations, **When** the user runs the command, **Then** a message `No attestations found` is printed
3. **Given** an unsigned attestation, **When** the user runs the command, **Then** the SIGNED column shows `no`
4. **Given** a signed attestation, **When** the user runs the command, **Then** the SIGNED column shows `yes`

### Edge Cases

- What happens when the predicate file path does not exist? — `werf attest sign` fails with `no such file` or `read predicate file: <error>`
- What happens when the signing key is invalid? — `werf attest sign` fails with `load signing key: <error>` detailing the PEM parsing error
- What happens when the registry is unreachable? — All commands fail with transport-level errors from `go-containerregistry`
- What happens when the attestation artifact has an unknown predicate type URI? — `werf attest ls` shows `(unknown)` in the PREDICATE TYPE column
- What happens if the fallback index does not exist? — `werf attest ls` uses an empty index and reports `No attestations found`
- How does concurrent attestation signing work? — The `Attach` function uses CAS (compare-and-swap) with retries to detect concurrent writes

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a `werf attest sign` command that creates a signed attestation and attaches it to an image
- **FR-002**: System MUST provide a `werf attest get` command that retrieves an attestation's predicate from an image
- **FR-003**: System MUST provide a `werf attest verify` command that verifies a signed attestation's signature and returns the predicate
- **FR-004**: System MUST provide a `werf attest ls` command that lists attestations attached to an image
- **FR-005**: All attest commands MUST accept `--repo` (required) to specify the container registry address
- **FR-006**: All attest commands MUST accept `--digest` or `--tag` (mutually exclusive) to identify the parent image
- **FR-007**: The `werf attest sign` command MUST accept `--predicate` (required), `--type` (required), `--sign-key` (required), and `--image` (required)
- **FR-008**: The `werf attest get` command MUST accept `--type` (required) and `--image` (optional)
- **FR-009**: The `werf attest verify` command MUST accept `--type` (required), `--key` (repeatable, required), and `--image` (optional)
- **FR-010**: The `werf attest ls` command MUST accept no type or key flags, only `--digest`/`--tag`
- **FR-011**: System MUST support predicate type resolution via short names: `openvex`, `slsaprovenance`, `slsaprovenance1`, `spdxjson`, `cyclonedx`
- **FR-012**: System MUST support predicate type resolution via full URIs (any URI containing `://`)
- **FR-013**: System MUST wrap predicate payloads in an in-toto Statement v1 (`https://in-toto.io/Statement/v1`) with subject referencing the parent image
- **FR-014**: System MUST wrap the in-toto statement in a DSSE envelope (`application/vnd.dsse.envelope.v1+json`)
- **FR-015**: System MUST sign the DSSE envelope using the provided signing key
- **FR-016**: System MUST support signing keys in PEM format: PKCS#8, EC, or RSA private keys
- **FR-017**: System MUST support signing keys from HashiCorp Vault via `hashivault://` scheme
- **FR-018**: System MUST support verification keys as PEM-encoded public keys (any algorithm supported by `sigstore/sigstore`)
- **FR-019**: System MUST attach attestations to images using the OCI fallback index mechanism (tag-based `sha256-<hex>`)
- **FR-020**: System MUST set the OCI artifact type to `application/vnd.dsse.envelope.v1+json` for attestation artifacts
- **FR-021**: System MUST support `--image` flag for per-image artifact indexing, allowing multiple images per repo
- **FR-022**: System MUST detect concurrent writes to the fallback index and retry with exponential backoff (up to 3 retries)
- **FR-023**: `werf attest ls` output MUST include PREDICATE TYPE, DIGEST, and SIGNED columns
- **FR-024**: `werf attest get` and `werf attest verify` MUST output the predicate to stdout
- **FR-025**: The existing `pkg/sbom/image/dsse.go` MUST delegate to `pkg/attestation/` to avoid code duplication

### Go-Specific Requirements *(when applicable)*

- All public functions MUST accept `context.Context` as the first parameter
- Errors MUST be wrapped with `fmt.Errorf("doing something: %w", err)`
- Use `samber/lo` helpers where appropriate
- Optional arguments use `<FunctionName>Options` struct — never functional options
- Add `var _ Interface = (*Impl)(nil)` compile-time check for each interface implementation

### Key Entities

- **DSSE Envelope**: A JSON structure with `payload` (base64), `payloadType`, and `signatures` array. Standard: `https://github.com/secure-systems-lab/dsse`
- **In-Toto Statement v1**: A JSON structure with `_type`, `predicateType`, `subject` (array of name+digest pairs), and `predicate`. Standard: `https://in-toto.io/Statement/v1`
- **Predicate**: The user-supplied attestation payload (e.g., OpenVEX, CycloneDX, SPDX, SLSA Provenance)
- **Fallback Index**: An OCI image index (manifest list) pushed under a tag `sha256-<hex>` that references OCI artifacts attached to the parent image digest
- **OCIStore**: Abstraction over OCI artifact attachment and retrieval using the fallback index mechanism
- **Signing Key**: A private key in PEM format (EC, RSA, Ed25519) or a HashiCorp Vault reference, used to produce DSSE signatures
- **Verification Key**: A public key in PEM format, used to verify DSSE signatures

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user can sign an attestation to an image with `werf attest sign` and immediately retrieve it with `werf attest get` — the output predicate matches the input
- **SC-002**: A user can sign an attestation to an image and verify it with `werf attest verify` using the correct public key — the output predicate matches the input
- **SC-003**: `werf attest verify` fails when the wrong public key is provided, with a clear error message
- **SC-004**: `werf attest ls` shows all attestations attached to an image, distinguishing signed from unsigned
- **SC-005**: All four commands produce appropriate error messages for missing arguments, invalid inputs, and network failures
- **SC-006**: SBOM subsystem (`pkg/sbom/image/dsse.go`) continues to function correctly after refactoring to use the shared `pkg/attestation/` package
- **SC-007**: The `Attach` function in `pkg/oci/artifact/fallback.go` handles concurrent writes with CAS retry mechanism
- **SC-008**: All unit tests pass via `task test:unit -- -run Attestation ./pkg/attestation/...`

## Assumptions

- Users have access to a container registry (Docker v2 compatible) with push/pull permissions
- Users generate their own signing keys externally — werf does not generate keys
- The OCI fallback index mechanism is the standard way werf attaches artifacts to images (pre-existing mechanism)
- Predicate files are plain text or JSON files on the local filesystem
- Parent images must already exist in the registry before attestation commands can be used
- `--image` flag is required for `sign` but optional for `get`/`verify` — when omitted, the first matching attestation of the requested type is returned
- `--image` is not supported by `ls` — all attestations for the digest are listed regardless of image name
- The `VerifyDSSE` function returns the first matching signature payload; it does not require all verifiers to match