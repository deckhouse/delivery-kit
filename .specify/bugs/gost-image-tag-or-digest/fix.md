# Bug Fix: Qualify GOST toggle scratch-image references

- **Slug**: gost-image-tag-or-digest
- **Fixed**: 2026-08-31
- **Assessment**: ./assessment.md
- **Status**: applied

## Summary

Qualified the scratch-image references in both GOST toggle E2E fixtures with the explicit `:latest` tag. This keeps the existing external-image validation contract intact while allowing the fixtures to load successfully.

## Changes

| File | Change | Notes |
|------|--------|-------|
| `test/e2e/sbom/_fixtures/gost_toggle/state0/werf.yaml` | modified | Changed `registry.werf.io/werf/scratch` to `registry.werf.io/werf/scratch:latest`. |
| `test/e2e/sbom/_fixtures/gost_toggle/state1/werf.yaml` | modified | Changed `registry.werf.io/werf/scratch` to `registry.werf.io/werf/scratch:latest`. |

## Diff Highlights

Both GOST toggle states now use:

```yaml
from: registry.werf.io/werf/scratch:latest
```

## Tests Added or Updated

- No tests added or updated. The assessment identified existing validation and GOST/SBOM coverage as sufficient.

## Local Verification

- Commands run: `git diff --check -- test/e2e/sbom/_fixtures/gost_toggle/state0/werf.yaml test/e2e/sbom/_fixtures/gost_toggle/state1/werf.yaml` → passed.
- Static fixture search: confirmed the only remaining unqualified `registry.werf.io/werf/scratch` references in the E2E YAML fixtures were the two updated files.
- Commands run: `task test:e2e paths="./test/e2e/sbom/..." labelFilter="gost"` → timed out after 120 seconds without producing output; the E2E environment did not provide a completed result.
- Manual checks: verified both `state0` and `state1` fixture files contain the explicitly tagged reference and retain their distinct GOST settings.

## Deviations from Assessment

The preferred remediation was applied without deviation. The requested E2E verification could not be completed because the scoped command timed out.

## Follow-ups

- Run `/speckit-bug-test slug=gost-image-tag-or-digest` in an environment where the SBOM GOST E2E dependencies and registry are available.
- Re-run the linked `e2e_simple` scenario when the authenticated CI failure details are available.
