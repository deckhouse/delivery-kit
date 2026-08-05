---
description: "Task list for SBOM documentation actualization"
---

# Tasks: SBOM Documentation Actualization

**Input**: Design documents from `/specs/014-sbom-documentation-actualization/`

**Prerequisites**: plan.md (required), spec.md (required for user stories)

**Organization**: Tasks are grouped by the type of documentation change.

## Format: `[ID] [Area] Description`

- **[Area]**: Which area this task belongs to (e.g., SBOM Page, CLI Help, Navigation)
- Include exact file paths in descriptions

## Path Conventions

- **SBOM page (English)**: `docs/pages_en/usage/build/sbom.md`
- **SBOM page (Russian)**: `docs/pages_ru/usage/build/sbom.md`
- **Build process page (English)**: `docs/pages_en/usage/build/process.md`
- **Build process page (Russian)**: `docs/pages_ru/usage/build/process.md`
- **CLI help text source**: `cmd/werf/sbom/{get,merge,validate}/` and `cmd/werf/root/root.go`
- **Generated CLI reference**: `docs/_includes/reference/cli/`
- **Sidebar navigation**: `docs/_data/sidebars/{_,}documentation.yml`
- **Config reference data**: `docs/_data/werf_yaml.yml`
- **Stapel instructions**: `docs/pages_en/usage/build/stapel/instructions.md`
- **Template engine docs**: `docs/pages_en/usage/project_configuration/werf_yaml_template_engine.md`

---

## Phase 1: Dedicated SBOM Documentation Page

**Purpose**: Create a comprehensive SBOM documentation page in both English and Russian

- [X] T001 Create `docs/pages_en/usage/build/sbom.md` — 141 lines covering global configuration, base image requirements, OCI storage format, GOST properties, caching behavior, and CLI commands overview
- [X] T002 Create `docs/pages_ru/usage/build/sbom.md` — Russian translation of the SBOM page with identical structure (141 lines)
- [X] T003 Remove inline SBOM section from `docs/pages_en/usage/build/process.md` and replace with cross-reference link to the new SBOM page (was ~62 lines, replaced with 1 line)
- [X] T004 Remove inline SBOM section from `docs/pages_ru/usage/build/process.md` and replace with cross-reference link to the new SBOM page (was ~62 lines, replaced with15 lines)

**Checkpoint**: SBOM page exists in both languages; build process page no longer has inline SBOM content.

---

## Phase 2: CLI Help Text Refresh

**Purpose**: Update the CLI help text for SBOM commands in Go source files

- [X] T005 [CLI] Update `cmd/werf/root/root.go` — change sbom short description from "Work with werf SBOM images" to "Work with SBOM artifacts"
- [X] T006 [CLI] Update `cmd/werf/sbom/get/get_docs.go` — clarify that `--repo` is required, document `--tag`/`--digest` mutually exclusive flags
- [X] T007 [CLI] Update `cmd/werf/sbom/merge/merge.go` — change docker config flag description from "pull SBOM images" to "pull SBOM artifacts"
- [X] T008 [CLI] Update `cmd/werf/sbom/merge/merge_docs.go` — document required flags (`--input`, `--ispras-format`, `--app-name`, `--app-version`, `--manufacturer`)
- [X] T009 [CLI] Update `cmd/werf/sbom/validate/validate_docs.go` — document required flags (`--path`, `--ispras-format`, `--check-vcs`)

**Checkpoint**: CLI help text source is updated in Go.

---

## Phase 3: Generated CLI Reference Includes

**Purpose**: Regenerate the CLI reference includes from the updated Go source

- [X] T010 [CLI] Regenerate `docs/_includes/reference/cli/werf_sbom.md` — updated short description
- [X] T011 [CLI] Regenerate `docs/_includes/reference/cli/werf_sbom.short.md` — updated short description
- [X] T012 [CLI] Regenerate `docs/_includes/reference/cli/werf_sbom_get.md` — added `--repo` requirement and `--tag`/`--digest` docs
- [X] T013 [CLI] Regenerate `docs/_includes/reference/cli/werf_sbom_merge.md` — added required flags docs, updated docker config description
- [X] T014 [CLI] Regenerate `docs/_includes/reference/cli/werf_sbom_validate.md` — added `--path`/`--ispras-format`/`--check-vcs` docs

**Checkpoint**: Generated CLI reference includes match the updated Go source.

---

## Phase 4: Navigation and Cross-References

**Purpose**: Update sidebar navigation and cross-references to point to the new SBOM page

- [X] T015 [Nav] Add SBOM entry to `docs/_data/sidebars/_documentation.yml` — under "Build" in both English and Russian sections
- [X] T016 [Nav] Add SBOM entry to `docs/_data/sidebars/documentation.yml` — under "Build" in both English and Russian sections
- [X] T017 [Nav] Update `docs/_data/werf_yaml.yml` — point SBOM configuration links from build process page anchors to the new dedicated SBOM page
- [X] T018 [Nav] Update `docs/pages_en/usage/build/stapel/instructions.md` — change SBOM cross-reference to use `{% true_relative_url %}` link to the new SBOM page
- [X] T019 [Nav] Add `os-pm` to the package ecosystem types list in `docs/_data/werf_yaml.yml`

**Checkpoint**: Navigation and cross-references are consistent.

---

## Phase 5: Incidental Fixes

**Purpose**: Fix issues discovered during the SBOM documentation work

- [X] T020 [Fix] Fix dead link to findutils shell pattern matching in `docs/pages_en/usage/project_configuration/werf_yaml_template_engine.md` — update URL from `findutils/manual/html_node/find_html/Shell-Pattern-Matching.html` to `Shell-Pattern-Matching.html`

**Checkpoint**: All incidental fixes are applied.

---

## Phase 6: Polish & Validation

**Purpose**: Final validation, formatting, and build checks

- [X] T021 Format code: `task format`
- [X] T022 Build check: `task build`
- [X] T023 Run `task doc:gen` to ensure CLI reference docs are up to date

---

## Dependencies & Execution Order

### Phase Dependencies

- **SBOM Page (Phase 1)**: No dependencies — can start immediately
- **CLI Help Text (Phase 2)**: No dependencies
- **Generated CLI Includes (Phase 3)**: Depends on Phase 2 (CLI help text source must be updated first)
- **Navigation (Phase 4)**: No dependencies on Phase 1-3 (sidebar and cross-references can be updated independently)
- **Incidental Fixes (Phase 5)**: No dependencies
- **Polish (Phase 6)**: Depends on all other phases

### Parallel Opportunities

- Phase 1, Phase 2, Phase 4, and Phase 5 can run in parallel (no overlapping files)
- Within Phase 1: T001 and T002 can run in parallel (different language files)
- Within Phase 2: T005, T006, T007, T008, T009 can run in parallel (different Go source files)
- Within Phase 3: T010-T014 can run in parallel (different generated include files)
- Within Phase 4: T015, T016, T017, T018, T019 can run in parallel (different data files)

---

## Notes

- All tasks are marked [x] as the feature already exists on the branch.
- The documentation is a docs-only feature — no Go business logic tests exist or are needed.
- The Russian SBOM page is a direct translation of the English page with identical structure.
- The dead link fix in `werf_yaml_template_engine.md` (T020) is an incidental discovery, not part of the core SBOM documentation scope.
- After this branch, `task doc:gen` should be run to regenerate CLI reference docs.