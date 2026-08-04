---
title: SBOM
permalink: usage/build/sbom.html
---

> **Note**: SBOM scanning and artifact generation is an experimental feature. Its behavior and configuration options may change in future releases.

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

## Base image requirements

When SBOM generation is enabled, every base image referenced via `from` or `fromImage` and every image referenced via `import` **must have an SBOM artifact attached in the registry**. There is no alternative to this requirement; the only exception is described below.

If an image has no attached SBOM and doesn't carry the label `io.deckhouse.internal.builder=true`, the build fails with:

```
the base image "example.registry.io/myimage:latest" must either have the label
"io.deckhouse.internal.builder" set to "true" or have an SBOM artifact attached;
to generate an SBOM for the base image, rebuild it with SBOM generation enabled
```

Rebuild the base image with `build.sbom.enable: true` to resolve this.

If the base image is `scratch`, it produces an empty SBOM with no components.

### Legacy exception (deprecated)

Two families of older Deckhouse builder images carry the `io.deckhouse.internal.builder=true` label but have no attached SBOM:

- `registry.deckhouse.io/container-factory/builder/golang` (and its tags)
- `registry.deckhouse.io/container-factory/builder/alpine` (and its tags)

Builds using these images still succeed today, but emit a deprecation warning:

```
The builder image "..." is DEPRECATED and it WILL CAUSE AN ERROR in the future.
Plan your migration to an up-to-date builder image.
```

Any other image that carries `io.deckhouse.internal.builder=true` but has no SBOM — including newer `container-factory` builder images — will fail with:

```
the base image "..." must have an SBOM artifact attached;
the image is a builder image but SBOM is required
```

Rebuild such images with `build.sbom.enable: true` to attach an SBOM.

## How the SBOM is stored

The SBOM is stored as an OCI artifact whose subject is the manifest of the target image. This makes it discoverable by any tool that understands the OCI referrers relationship.

### Artifact structure

The CycloneDX document is wrapped in an [in-toto](https://in-toto.io/) statement and then in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope before being stored. The layer carrying the envelope has the media type `application/vnd.dsse.envelope.v1+json`; the in-toto predicate type is `https://cyclonedx.org/bom/v1.6`.

### Registry compatibility

werf always uses a tag-based index to store and retrieve SBOM artifacts, regardless of whether the registry supports the OCI referrers API. No registry-specific configuration is required. Additionally, werf sets the OCI `subject` field on the artifact manifest, which allows external tools that understand the OCI referrers specification to discover and access the SBOM directly. Both access paths are maintained automatically on every push.

### Artifact annotations

Each SBOM artifact carries the following annotations on its descriptor in the index:

| Annotation | Contents |
|---|---|
| `io.werf.image-name` | Name of the image this SBOM belongs to |
| `io.werf.checksum` | Content checksum of the image |
| `io.werf.target-platform` | Target CPU/OS platform (e.g. `linux/amd64`) |

### Multi-platform images

When building a multi-platform image, werf generates a separate SBOM artifact for each platform. Each platform SBOM is annotated with its `io.werf.target-platform` value so that tooling can retrieve the correct one.

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

## Caching and rebuilds

Toggling `build.sbom.enable` changes the stage digest, so enabling or disabling SBOM generation invalidates the cache and triggers a full rebuild.

While SBOM generation is off (the default), stage digests are identical to those of a project that has never used this feature. Caches built before SBOM support was introduced remain valid and continue to be reused. If you enable the feature and later turn it off again, digests return to their original values.

Changing GOST properties (`sbom.gost`) does not affect stage digests. Cached stages are reused, and the SBOM document is regenerated with the updated properties during the SBOM step.

## Inspecting and merging SBOMs

[`werf sbom get`]({{ "/reference/cli/werf_sbom_get.html" | true_relative_url }}) retrieves the SBOM for an image described in `werf.yaml` and prints it to stdout. The SBOM is read as an OCI artifact from the container registry, so `--repo` is required. If no SBOM is found for the requested image, the command automatically triggers a build to generate one. You can select a specific version with `--tag` or `--digest`; these flags are mutually exclusive.

[`werf sbom merge`]({{ "/reference/cli/werf_sbom_merge.html" | true_relative_url }}) assembles a product-level SBOM from several per-image SBOMs. It takes a JSON file that maps image names to sha256 digests, pulls the individual SBOMs from the registry, and merges them into a single CycloneDX document with dependency graphs preserved. Two ISPRAS output formats are available: `container` (hierarchical, each image becomes a top-level component with nested packages) and `oss` (flat, all packages deduplicated into one list). GOST `attack_surface` and `security_function` properties are aggregated bottom-up with the precedence `yes > indirect > no`.

[`werf sbom validate`]({{ "/reference/cli/werf_sbom_validate.html" | true_relative_url }}) checks a CycloneDX JSON file against ISPRAS schemas. It runs sbom-checker inside a Docker container and reports any violations. Both `oss` and `container` SBOM types are supported.
