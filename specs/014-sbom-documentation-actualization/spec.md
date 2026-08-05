# Feature Specification: SBOM Documentation Actualization

**Feature Branch**: `docs/sbom/actualize-documentation`

**Created**: 2026-08-05

**Status**: migrated

**Input**: Reverse-engineered from branch `docs/sbom/actualize-documentation` (12 commits, 21 files changed, +345/-138 against `origin/main`).

## Project Context

**Delivery Kit** is a Go CLI tool for full-cycle CI/CD to Kubernetes. It is built on top of werf with Deckhouse Platform extensions. The documentation is maintained as a Jekyll-based site in `docs/`:

- **User-facing docs**: `docs/pages_{en,ru}/usage/` — English and Russian documentation pages
- **CLI reference docs**: `docs/_includes/reference/cli/` — generated help text for every CLI command
- **Sidebar navigation**: `docs/_data/sidebars/` — sidebar structure for the documentation site
- **Config reference data**: `docs/_data/werf_yaml.yml` — structured data for `werf.yaml` configuration reference
- **CLI help text source**: `cmd/werf/sbom/` — Go source files that define CLI command help text

## User Scenarios & Testing *(mandatory)*

### User Story 1 — User finds comprehensive SBOM documentation in one place (Priority: P1)

A user configuring SBOM for their project needs to understand the global configuration, base image requirements, storage format, GOST properties, and caching behavior. Previously, this information was scattered across the build process page (inline) and CLI help text. Now, a dedicated SBOM page covers all these topics.

**Why this priority**: The primary motivation for this branch — SBOM documentation was previously inline in the build process page, which was too long and lacked depth. Users had to search for SBOM-related content.

**Acceptance Scenarios**:

1. **Given** a user visits the SBOM documentation page, **When** they read the global configuration section, **Then** they understand how to enable SBOM and set the output standard.
2. **Given** a user needs to know base image requirements, **When** they read the base image section, **Then** they learn that every base image must have an SBOM artifact attached.
3. **Given** a user encounters a legacy Deckhouse builder image without SBOM, **When** they read the legacy exception section, **Then** they understand that a deprecation warning is expected and migration is required.

---

### User Story 2 — CLI help text is accurate and discoverable (Priority: P2)

A user running `werf sbom get --help`, `werf sbom merge --help`, or `werf sbom validate --help` sees clear, up-to-date help text that documents required flags, optional flags, and the command's purpose.

**Why this priority**: CLI help text is the first line of documentation for users. Inaccurate or missing flag documentation leads to confusion and support requests.

**Acceptance Scenarios**:

1. **Given** a user runs `werf sbom get --help`, **When** they read the description, **Then** they see that `--repo` is required and that `--tag`/`--digest` are mutually exclusive selectors.
2. **Given** a user runs `werf sbom merge --help`, **When** they read the description, **Then** they see the ISPRAS output format options and the list of required flags (`--input`, `--ispras-format`, `--app-name`, `--app-version`, `--manufacturer`).
3. **Given** a user runs `werf sbom validate --help`, **When** they read the description, **Then** they see that `--path` and `--ispras-format` are required and that `--check-vcs` is available.

---

### User Story 3 — Navigation and cross-references are consistent (Priority: P3)

A user navigating the documentation site or following links from other pages finds the SBOM page in the sidebar under "Build", and all cross-references from `werf.yaml` config docs, Stapel instructions, and the build process page point to the new dedicated page.

**Why this priority**: Broken navigation and stale cross-references degrade the user experience and make the documentation feel unmaintained.

**Acceptance Scenarios**:

1. **Given** a user opens the documentation sidebar, **When** they look under "Build", **Then** they see an "SBOM" entry linking to the new page.
2. **Given** a user is reading the `werf.yaml` configuration reference, **When** they click the SBOM configuration "details" link, **Then** they are taken to the dedicated SBOM page.
3. **Given** a user is reading the Stapel instructions, **When** they click the SBOM link, **Then** they are taken to the dedicated SBOM page.

---

### Edge Cases

- What happens when the user has both English and Russian documentation? Both language versions are updated identically.
- What happens when the CLI help text is regenerated from Go source? The generated includes in `docs/_includes/` are updated to match the Go source changes.
- What happens if the user is on an older version of werf that doesn't have SBOM support? The documentation clearly marks SBOM as experimental and notes that the feature is behind a configuration flag.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The dedicated SBOM page MUST document global configuration (`build.sbom.enable`, `standard`), scanner defaults, base image requirements, storage format, GOST properties, and caching behavior.
- **FR-002**: The SBOM page MUST exist in both English (`docs/pages_en/usage/build/sbom.md`) and Russian (`docs/pages_ru/usage/build/sbom.md`).
- **FR-003**: The CLI help text for `werf sbom`, `werf sbom get`, `werf sbom merge`, and `werf sbom validate` MUST be updated in the Go source files (`cmd/werf/sbom/`).
- **FR-004**: The generated CLI reference includes (`docs/_includes/reference/cli/`) MUST be regenerated to match the updated Go source.
- **FR-005**: The sidebar navigation (`docs/_data/sidebars/{_,}documentation.yml`) MUST include an SBOM entry under "Build" in both English and Russian.
- **FR-006**: The `werf.yaml` configuration reference (`docs/_data/werf_yaml.yml`) MUST point SBOM-related links to the new dedicated page instead of the build process page anchors.
- **FR-007**: The inline SBOM section in the build process page (`docs/pages_{en,ru}/usage/build/process.md`) MUST be replaced with a cross-reference link to the new SBOM page.
- **FR-008**: The Stapel instructions (`docs/pages_en/usage/build/stapel/instructions.md`) MUST cross-reference the new SBOM page.
- **FR-009: The `os-pm` package ecosystem type MUST be documented in the `werf.yaml` package types list.

### Key Entities

- **SBOM Documentation Page**: A Jekyll page under `docs/pages_{en,ru}/usage/build/sbom.md` that comprehensively documents SBOM feature.
- **CLI Help Text**: Go source files in `cmd/werf/sbom/{get,merge,validate}/` that define the `Long` and `LongMD` fields for cobra commands.
- **Generated CLI Includes**: Files in `docs/_includes/reference/cli/` that are regenerated from Go source and included in the documentation site.
- **Sidebar Entry**: A navigation entry in the Jekyll sidebar data files that links to the SBOM page.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The SBOM documentation page exists in both English and Russian and renders correctly in the Jekyll site.
- **SC-002**: All CLI help text updates are reflected in the generated reference includes.
- **SC-003**: The sidebar navigation includes an SBOM entry that links to the correct URL.
- **SC-004**: All cross-references from `werf.yaml` config, Stapel instructions, and build process page point to the new SBOM page.
- **SC-005**: The inline SBOM content is removed from the build process page and replaced with a concise cross-reference link.

## Assumptions

- The Jekyll documentation site is built and deployed separately from the CLI binary — changes to documentation pages and CLI help text are independent.
- The `docs/_includes/reference/cli/` files are generated from Go source using `task doc:gen` — the generation process is assumed to be correct.
- The Russian documentation page is a direct translation of the English page with the same structure and content coverage.
- The `os-pm` ecosystem type addition in `docs/_data/werf_yaml.yml` is a minor documentation fix that was discovered during the SBOM documentation work.