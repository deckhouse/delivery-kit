# Config Interface Contract: VEX in werf.yaml

**Date**: 2026-07-31
**Contract Type**: CLI Configuration Schema

## Overview

This contract defines how users declare VEX documents in `werf.yaml`. It follows the same pattern as the existing `sbom` per-image configuration.

## Syntax

```yaml
image: <image-name>
dockerfile: <path>
# Optional: path to an OpenVEX document relative to Git repository root
vex: <path-to-vex-file>
```

### Rules

1. The `vex` field is **optional** at the image level.
2. The value MUST be a **string** (path).
3. The path MUST be **relative to the Git repository root**.
4. The path MUST point to a file **tracked by Git**.
5. The file MUST be a valid **OpenVEX JSON-LD** document.

### Examples

```yaml
# Example 1: Single image with VEX
image: my-app
dockerfile: Dockerfile
vex: vex/my-app.openvex.json
```

```yaml
# Example 2: Multiple images, some with VEX
image: backend
dockerfile: backend/Dockerfile
vex: vex/backend.openvex.json

image: frontend
dockerfile: frontend/Dockerfile
# No VEX for frontend
```

```yaml
# Example 3: Image with both SBOM and VEX (fully valid)
image: secured-app
dockerfile: Dockerfile
sbom:
  standard: CycloneDX@1.6
vex: vex/secure.openvex.json
```

### Validation Errors

| Input | Error Message |
|-------|---------------|
| `vex:` (empty) | `"image \"<name>\": vex path is empty"` |
| `vex: nonexistent.json` | `"image \"<name>\": VEX file not found: \"nonexistent.json\""` |
| `vex: untracked.json` | `"image \"<name>\": VEX file \"untracked.json\" must be tracked by Git"` |
| `vex: empty.json` | `"image \"<name>\": VEX file \"empty.json\" is empty"` |
| `vex: invalid.json` | `"image \"<name>\": VEX file \"invalid.json\" is not valid: <detail>"` |

### Backward Compatibility

- Existing `werf.yaml` files without `vex` fields work **identically** after this change (FR-009, SC-005).
- The `vex` field is omitted when empty — no serialization changes to existing configs.

## Related

- Data model: [data-model.md](../data-model.md)
- Feature spec: [spec.md](../spec.md)