# Implementation Plan: SBOM Documentation Actualization

**Branch**: `docs/sbom/actualize-documentation` | **Date**: 2026-08-05 | **Spec**: [spec.md](spec.md)

**Input**: Reverse-engineered from branch `docs/sbom/actualize-documentation` (12 commits, 21 files changed, +345/-138 against `origin/main`).

## Summary

The SBOM feature documentation was previously inline in the build process page (`docs/pages_{en,ru}/usage/build/process.md`), making the page too long and lacking dedicated depth on SBOM-specific topics. This feature extracts SBOM content into a dedicated page, refreshes the CLI help text, updates navigation and cross-references, and fixes a dead link discovered during the work.

## Technical Context

**Language/Version**: Go 1.24.10 (CLI help text source), Markdown + Jekyll (documentation site)

**Documentation Stack**:
- **Jekyll-based static site** in `docs/` — uses Liquid templates, YAML sidebars, and Markdown pages
- **Dual language support**: English (`pages_en/`) and Russian (`pages_ru/`) — both must be updated identically
- **CLI help text**: Defined in Go source (`cmd/werf/sbom/`) and regenerated into `docs/_includes/reference/cli/` via `task doc:gen`
- **Config reference data**: `docs/_data/werf_yaml.yml` — structured YAML data for `werf.yaml` configuration reference, referenced by the Jekyll site

**Key files affected**:

| Area | Files | Change |
|------|-------|--------|
| New SBOM page | `docs/pages_{en,ru}/usage/build/sbom.md` | Created (141 lines each) |
| Build process page | `docs/pages_{en,ru}/usage/build/process.md` | Removed inline SBOM section, replaced with cross-reference |
| CLI help text (Go) | `cmd/werf/sbom/get/get_docs.go`, `cmd/werf/sbom/merge/merge_docs.go`, `cmd/werf/sbom/merge/merge.go`, `cmd/werf/sbom/validate/validate_docs.go`, `cmd/werf/root/root.go` | Updated descriptions, documented required flags |
| Generated CLI includes | `docs/_includes/reference/cli/werf_sbom{,.short,_get,_merge,_validate}.md` | Regenerated from Go source |
| Sidebar navigation | `docs/_data/sidebars/{_,}documentation.yml` | Added SBOM entry under "Build" |
| Config reference | `docs/_data/werf_yaml.yml` | Updated SBOM links, added `os-pm` to ecosystem types |
| Cross-references | `docs/pages_en/usage/build/stapel/instructions.md`, `docs/pages_en/usage/project_configuration/werf_yaml_template_engine.md` | Updated SBOM link, fixed dead link |

## Repository Structure Affecting This Feature

```
docs/
├── _data/
│   ├── sidebars/
│   │   ├── _documentation.yml      # [MODIFY] Add SBOM entry (English + Russian)
│   │   └── documentation.yml       # [MODIFY] Add SBOM entry (English + Russian)
│   └── werf_yaml.yml               # [MODIFY] Update SBOM links, add os-pm to types
├── _includes/reference/cli/
│   ├── werf_sbom.md                # [REGENERATE] Updated short description
│   ├── werf_sbom.short.md          # [REGENERATE] Updated short description
│   ├── werf_sbom_get.md            # [REGENERATE] Updated help text
│   ├── werf_sbom_merge.md          # [REGENERATE] Updated help text + docker config flag
│   └── werf_sbom_validate.md       # [REGENERATE] Updated help text
├── pages_en/usage/build/
│   ├── process.md                  # [MODIFY] Remove inline SBOM, add cross-reference
│   ├── sbom.md                     # [NEW] Dedicated SBOM documentation page
│   └── stapel/instructions.md      # [MODIFY] Update SBOM cross-reference link
├── pages_ru/usage/build/
│   ├── process.md                  # [MODIFY] Remove inline SBOM, add cross-reference
│   └── sbom.md                     # [NEW] Dedicated SBOM documentation page (Russian)
└── pages_en/usage/project_configuration/
    └── werf_yaml_template_engine.md # [MODIFY] Fix dead link to findutils

cmd/werf/
├── root/root.go                    # [MODIFY] Update sbom short description
└── sbom/
    ├── get/get_docs.go             # [MODIFY] Update help text
    ├── merge/merge.go              # [MODIFY] Update docker config flag description
    ├── merge/merge_docs.go         # [MODIFY] Update help text
    └── validate/validate_docs.go   # [MODIFY] Update help text
```

## Complexity Assessment

- **File count**: 21 files changed (2 created, 19 modified)
- **Line count**: +345 lines, -138 lines
- **Dependency depth**: Low — documentation-only changes, no code logic changes
- **Risk**: Low — no Go business logic changes, only CLI help text and documentation
- **Language coverage**: Both English and Russian pages updated in parallel

## Execution Order

1. Create dedicated SBOM documentation page (English + Russian)
2. Remove inline SBOM section from build process page, add cross-reference
3. Update CLI help text in Go source files
4. Regenerate CLI reference includes
5. Update sidebar navigation
6. Update cross-references in werf.yaml config data, Stapel instructions
7. Fix dead link in werf_yaml_template_engine.md
8. Add `os-pm` to package ecosystem types in werf.yaml config data