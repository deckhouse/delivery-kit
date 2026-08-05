# Implementation Plan: Enforce os-pm Determinism via Spec+Lock Files

**Branch**: `feat/config/enforce-pm-determinism` | **Date**: 2026-07-16 | **Spec**: `specs/006-enforce-pm-determinism/spec.md`

**Input**: Reverse-engineered from the diff between `feat/config/enforce-pm-determinism` and `origin/main` (commit `714fe86b6`).

**Note**: This plan is retroactively reconstructed from existing implementation.

## Summary

Transform the `os-pm` package type from a flat, ad-hoc list-of-strings specification (`packages: ["curl", "jq"]` → `pm install curl; pm install jq`) to a deterministic file-based spec+lock model (`pm.yaml` + `pm.lock` → `pm sync --from /pm.lock`), aligning it with all other package ecosystems (`go-mod`, `python-uv`, `rust-cargo`, etc.). This ensures reproducible, verifiable dependency resolution for OS-level packages.

## Technical Context

**Language/Version**: Go 1.24.10

**Primary Dependencies**:
- **Container building**: `containers/buildah` (werf fork: `werf/3p-buildah`), `containers/storage`, `containers/image`
- **SBOM**: `CycloneDX/cyclonedx-go`, `facebookincubator/nvdtools`
- **Utilities**: `samber/lo`, `werf/common-go`, `go-git/go-git`

**Storage**: OCI container registry (Docker v2, ECR), local git repository, Buildah container storage

**Testing**: Ginkgo + Gomega for unit tests and e2e tests

**Target Platform**: Linux (amd64/arm64) via Buildah

## Constitution Check

N/A — feature already exists on its branch.

## Project Structure

### Documentation (this feature)

```text
specs/006-enforce-pm-determinism/
├── spec.md              # This file (migrated)
├── plan.md              # This file (migrated)
└── tasks.md             # Task list (migrated)
```

### Source Code (changed files)

```text
pkg/config/
├── packages_directive.go           # Remove PackagesSpec, add os-pm to ecosystems
├── packages_commands.go            # Unify command generation via ecosystem registry
├── raw_packages_directive.go       # Remove fillOSPMSpec, unify fillFileBasedSpec
├── raw_packages_directive_test.go  # Update tests for new spec/lock model
├── stapel_image_base.go            # Add OSPMLockPath(), keep HasOSPMPackages()
└── helpers_test.go                 # Minor fix: return err instead of Expect

pkg/build/
├── build_phase.go                  # hasOsPmPackages bool → osPmLockPath string
└── sbom_step.go                    # Pass lock path to osPm.CollectBOM

pkg/sbom/packages/os_pm/
├── os_pm.go                        # Rename ParsePmInstalledJSON → ParsePmLockJSON
├── collect.go                      # Read pm.lock from container instead of pm info
├── os_pm_test.go                   # Update tests for new parser name and format
└── testdata/pm_info_installed.json # Add metadata+packages envelope

pkg/sbom/managedinput/
└── managedinput.go                 # Already dynamic via Ecosystems() — no changes needed
                                    # (os-pm gets a cataloger automatically)

test/e2e/sbom/
├── lifecycle_test.go               # Update hash expectations
├── packages_test.go                # Update hash and error message expectations
└── _fixtures/inject/               # Add pm.lock files to all fixture dirs
```

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| N/A | Feature follows established patterns | — |
