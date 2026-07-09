## ADDED Requirements

### Requirement: Stage digest includes SBOM enable marker when SBOM is enabled

The stage digest SHALL incorporate a conditional SBOM marker when `build.sbom.enable=true`.
When `build.sbom.enable=false` (default), the stage digest SHALL NOT include any SBOM-related marker, preserving backward compatibility with existing cache.

#### Scenario: SBOM enabled after previously being disabled

- **WHEN** a user sets `build.sbom.enable: true` in `werf.yaml` and triggers a build
- **AND** the same image was previously built and cached with `build.sbom.enable: false`
- **THEN** the stage digest for each image SHALL differ from the cached stages
- **AND** all stages SHALL be rebuilt with SBOM generation enabled
- **AND** SBOM artifacts SHALL be generated and attached to the published images

#### Scenario: SBOM disabled build reuses existing cache

- **WHEN** a user triggers a build with `build.sbom.enable: false`
- **AND** the same image was previously built and cached with `build.sbom.enable: false`
- **THEN** the stage digest for each image SHALL remain unchanged
- **AND** previously cached stages SHALL be reused
- **AND** no SBOM artifacts SHALL be generated

#### Scenario: SBOM enabled after previously being enabled (same config)

- **WHEN** a user triggers a build with `build.sbom.enable: true`
- **AND** the same image was previously built and cached with `build.sbom.enable: true`
- **THEN** the stage digest SHALL remain unchanged (assuming all other cache inputs are identical)
- **AND** previously cached stages SHALL be reused
- **AND** the SBOM artifacts from the cached build SHALL be preserved

### Requirement: SBOM enable state is the only SBOM config affecting stage cache

GOST configuration, SBOM standard selection, and per-image SBOM overrides SHALL NOT affect the stage digest.

#### Scenario: GOST config changes with SBOM enabled

- **WHEN** a user modifies `build.sbom.gost` settings in `werf.yaml`
- **AND** `build.sbom.enable` remains `true`
- **THEN** the stage digest SHALL NOT change (cached stages remain valid)
- **AND** the SBOM artifact checksum SHALL change
- **AND** SBOM artifacts SHALL be regenerated during the converge step
