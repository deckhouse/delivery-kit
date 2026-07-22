# Contracts: Not Enforce pm Determinism

**Phase**: Phase 1 — Design & Contracts
**Date**: 2026-07-22
**Spec**: `specs/009-not-enforce-pm-determinism/spec.md`

## Overview

This document describes the user-facing YAML configuration contract for `os-pm` package directives in `werf.yaml`. The contract changes as part of the revert from the file-based spec+lock model back to the inline syntax.

## YAML Configuration Contract

### Inline Syntax (reverted)

The `os-pm` directive accepts a list of package names under the `spec` key, with optional version constraints:

```yaml
packages:
  - type: os-pm
    spec:
      - curl==8.12.1
      - jq
```

**Rules**:
- `type: os-pm` — required, identifies the package ecosystem
- `spec` — required, a YAML list of strings (package names), each may include version constraints like `==`, `>=`, `<=`, etc.
- `workdir` — NOT accepted; specifying it MUST produce a validation error
- `lock` — NOT accepted; lock files are not used for `os-pm`

### Rejected Syntax (was accepted by 006 feature)

The following syntax forms MUST be rejected:

```yaml
# Rejected: file-based spec+lock model no longer applies to os-pm
packages:
  - type: os-pm
    workdir: /
    spec: pm.yaml
    lock: pm.lock
```

```yaml
# Rejected: spec cannot be a list of strings in combination with a string spec field
packages:
  - type: os-pm
    spec: [curl==8.12.1, jq]    # accepted — list form
    # spec: pm.yaml would be rejected — ambiguous (list vs string)
    lock: pm.lock               # rejected — lock not used for os-pm
```

### Command Contract (internal, for reference)

For `os-pm` directives, the build phase generates a single command via `InstallCmd`:

```shell
PACKAGES_VERSION="${PACKAGES_VERSION:-$(stapel_cat /run/secrets/PACKAGES_VERSION 2>/dev/null || true)}" \
REGISTRY="${REGISTRY:-$(stapel_cat /run/secrets/REGISTRY 2>/dev/null || true)}" \
pm install curl==8.12.1 jq \
&& pm info --installed --json > /var/lib/pm/installed.json
```

For file-based ecosystems (e.g. `go-mod`):

```shell
cd /app && go mod download
```

All ecosystem types are handled by the same `InstallCmd(workdir, specFile, specList)` function — no special-casing.

### SBOM Contract (internal, for reference)

SBOM collection for `os-pm` reads `/var/lib/pm/index.json` — a file that `pm` writes itself with the current state of installed packages:

```shell
# During SBOM collection (via ReadFileFromImage):
# Read /var/lib/pm/index.json
```

Expected file format (flat JSON, keys = package names, values = package info):

```json
{
  "curl": { "name": "curl", "version": "8.5.0", ... },
  "jq":   { "name": "jq",   "version": "1.7.1", ... }
}
```

This file is parsed by `ParsePmInstalledJSON`. No separate capture command is run — `pm` maintains this file itself.

Expected output format:

```json
{
  "curl": { "name": "curl", "version": "8.5.0", ... },
  "jq":   { "name": "jq",   "version": "1.7.1", ... }
}
```

This flat JSON object (keys = package names, values = package info) is parsed by `ParsePmInstalledJSON`. The `pm` commands are run during the build stage, mirroring how other ecosystems run their install commands.

**Note**: We do not make assumptions about `pm`'s internal filesystem layout. We interact with `pm` exclusively through its CLI commands and parse their structured output.

### API Surface

The revert changes the following internal Go API signatures:

| Function | Before | After |
|----------|--------|-------|
| `osPm.CollectBOM(ctx, backend, imageRef, lockPath)` | 4 args (includes lockPath string) | 3 args (no lockPath) — reads captured output of `pm` commands instead |
| `sbomStep.ConvergeWithMerge(ctx, ..., osPmLockPath string, ...)` | `string` param | `osPmEnabled bool` param |
| `buildPhase.convergeImageSbom()` | `osPmLockPath = .OSPMLockPath()` | `hasOsPmPackages = .HasOSPMPackages()` |
| `StapelImageBase.OSPMLockPath()` | ✅ exists | ❌ removed |
| `PackagesDirective.validate()` | Unified for all types | Unified via ecosystem flags (no special-casing) |
| `PackageEcosystem.InstallCmd` | `func(workdir, spec string) string` | `func(workdir, specFile string, specList []string) string` — unified for all types |
| `PackageEcosystem.SkipWorkdir/SkipSpec/SkipLock` | ❌ do not exist | ❌ removed (not needed) |
| `PackageEcosystem.PackagesInstallCmd` | ❌ does not exist | ❌ removed (merged into `InstallCmd`) |