---
title: SBOM
permalink: usage/build/sbom.html
---

> **EXPERIMENTAL:** SBOM scanning and artifact generation is an experimental feature. The behavior and configuration options may change in future releases.

To enable scanning and generation of SBOM artifacts during the build process, you need to configure the global `build.sbom` section and, optionally, per-image components.

The scanning result is saved as an OCI artifact in the container registry, attached to the corresponding image. **The `--repo` flag is required** when SBOM generation is enabled. If `--repo` is not specified, the build fails with:

```
SBOM generation requires a container registry (specify --repo)
```

No local image with a `-sbom` suffix is created.

## Global project configuration (`build.sbom`)

The following options enable the scanning process for all images in the project:
1. Set `build.sbom.enable: true` to activate the feature.
2. Specify the output standard via `standard: cyclonedx@1.6` (currently only `cyclonedx@1.6` is supported).

```yaml
project: werf-sbom-meta-example
configVersion: 1
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
```

Currently, this option uses the following _defaults_:

| Property                          | Value                                                                                  |
|-----------------------------------|----------------------------------------------------------------------------------------|
| **Scanner**                       | syft                                                                                   |
| **Scanner Image**                 | anchore/syft:v1.45.1                                                           |
| **Image Pull Policy**             | `PullIfMissing`                                                                        |
| **Data Source Connection Method** | daemon + socket via volume (for Docker) |
| **Path in Source Image**          | OS root                                                                                |
| **Scan Settings**                 | [link](https://github.com/anchore/syft/wiki/Configuration#list-of-configurable-values) |
| **Output Standard**               | `CycloneDX@1.6`                                                                        |
| **Output Format**                 | `JSON`                                                                                 |

## GOST security properties (`sbom.gost`)

To comply with GOST safety standards, you can configure mandatory security properties for all components in the SBOM. These properties will be injected into all direct components of the final SBOM. By default, both generated and user-defined SBOMs are enriched with `attackSurface=yes` and `securityFunction=yes`, unless specified otherwise at the project (meta) or image level.

1. `attackSurface`: The attack surface property (`yes` | `no` | `indirect`).
2. `securityFunction`: The security function property (`yes` | `no` | `indirect`).

You can define these globally in `build.sbom.gost` or per-image in `image.sbom.gost`. Image-level configuration overrides global configuration.

> **NOTE:** GOST properties integration is experimental and strictly tied to the `cyclonedx@1.6` standard.

Example:
```yaml
build:
  sbom:
    enable: true
    standard: cyclonedx@1.6
    gost:
      attackSurface: yes
      securityFunction: no
```
