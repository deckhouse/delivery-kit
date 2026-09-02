---
title: SBOM roles and workflow
permalink: usage/build/sbom_workflow.html
---

SBOM work is split between two roles:

| Role | Responsible for | What they do | What they get |
|------|-----------------|--------------|---------------|
| **Module developer** | the module SBOM | declares dependencies declaratively and builds their images | **per-image SBOMs** (CycloneDX 1.6) in the registry, next to each image |
| **SBOM owner** | the product SBOM | aggregates the per-image SBOMs of the required images and validates the result | a **merged SBOM** (ISPRAS format) that passes ISPRAS validation |

The roles are independent: the module developer never runs merge/validate, and the
SBOM owner never builds images. All the SBOM owner needs from the developers is
to know **which images** (by their digests) make up the product.

```
Module developer:               dk build   [→ dk sbom get]
                                    │
                                    ▼   per-image SBOMs in the registry
SBOM owner:                     dk sbom merge  →  dk sbom validate
```

## Module developer flow

You are responsible for a module (application) and its images. Your task is to
build the images so that each of them gets a complete per-image SBOM in the
registry.

### Prerequisites

- **a container registry with write access** — images and SBOM artifacts are
  published there (the `--repo` flag / the `WERF_REPO` variable);
- **VCS external references enrichment** — set the `WERF_EXTERNAL_REFS_SERVER_URL`
  environment variable (the URL of the enrichment service); it is required when
  SBOM is enabled — without it the build fails (see
  [VCS external references enrichment]({{ "/usage/build/sbom.html#vcs-external-references-enrichment" | true_relative_url }})).

| Variable | Purpose | Required |
|----------|---------|----------|
| `WERF_REPO` | registry for images and SBOM artifacts | yes |
| `WERF_EXTERNAL_REFS_SERVER_URL` | URL of the VCS external refs enrichment service | yes — the build fails without it |

```bash
export WERF_REPO="registry.example.com/my-project"
export WERF_EXTERNAL_REFS_SERVER_URL="https://purl-resolver.example.com/"
```

#### Base images

**Classification.** Base images come in two flavors, and the flow differs
between them:

- **builder** images — the `packages` stage and shell instructions run in them;
  the SBOM of an image built on top of them may include **build dependencies**
  (build-deps: compilers, `*-devel` packages, and so on);
- **final** (runtime, e.g. distroless) images — the base of the shipped image;
  its SBOM contains runtime dependencies only.

**Requirements:**

- **Delivery Kit does not ship the `pm` package manager.** If an image uses
  `packages: type: os-pm`, its base image must provide the `pm` binary in `$PATH`
  (see the [`packages` directive]({{ "/usage/build/stapel/instructions.html#installing-binary-packages" | true_relative_url }}));
- **every base/import image must have an SBOM artifact attached** in the
  registry — otherwise a build with SBOM enabled fails; such images must be
  built with `build.sbom.enable: true` (see
  [Base image requirements]({{ "/usage/build/sbom.html#base-image-requirements" | true_relative_url }}));
- file-based ecosystems (`go-mod` and others) do not need `pm` — they need the
  corresponding toolchain in the base image (for example, Go for
  `go mod download`).

#### Technical limitations

See the [Technical limitations]({{ "/usage/build/sbom.html#technical-limitations" | true_relative_url }})
section on the SBOM page.

### Step 1. Declare dependencies in `werf.yaml`

|  |  |
|---|---|
| **Input** | module sources |
| **What to do** | enable SBOM and declare all dependencies declaratively |
| **Output** | a `werf.yaml` where every dependency is a controlled input |

Enable SBOM with the [`build.sbom`]({{ "/usage/build/sbom.html" | true_relative_url }})
section. The section applies to the whole `werf.yaml`: by setting it, you move
**all images of the project** into the SBOM flow. Declare dependencies via
[`packages`]({{ "/usage/build/stapel/instructions.html#installing-binary-packages" | true_relative_url }}):

- OS packages — as an inline list via `os-pm`;
- language dependencies — via file-based types (`go-mod` and others);
- bind the `packages` stage to the language dependency manifests via
  `stageDependencies`.

### Step 2. Build the images: `dk build`

|  |  |
|---|---|
| **Input** | sources + the `werf.yaml` from step 1 |
| **Command** | `dk build` |
| **Output** | images in the registry; a per-image SBOM artifact next to each image |

For each image, at build time Delivery Kit:

- records the dependencies declared in `packages` (syft catalogers over
  manifests/lock files, the os-pm cataloger);
- enriches components with GOST security properties (`attackSurface`,
  `securityFunction`);
- performs purl resolving: enriches VCS external references via the service from
  `WERF_EXTERNAL_REFS_SERVER_URL`;
- signs the SBOM if a key is provided (`--sign-key`, optionally `--sign-cert`),
  and publishes the SBOM artifact to the registry, associated with the image
  digest.

**Expected result:** the build finishes without errors; per-image SBOMs are
published to the registry along with the images. The module developer's task
ends here.

### Step 3 (optional). Self-check: `dk sbom get`

|  |  |
|---|---|
| **Input** | an image name from `werf.yaml` |
| **Command** | `dk sbom get <image>` |
| **Output** | the image SBOM — plain CycloneDX 1.6 JSON |

Optionally verify that your module's SBOM is complete:

```bash
dk sbom get <image> > sbom.json
```

`sbom get` downloads the SBOM from the registry (generated at step 2) to
stdout. The SBOM is always associated with the image **digest**; the name from
`werf.yaml` is a convenient label: Delivery Kit resolves it to the digest of the
current build and finds the SBOM by it. If the images are not built yet, the
command first runs the standard build conveyor, just like `dk build`.

**Expected result:** valid JSON with `"bomFormat": "CycloneDX"` and
`"specVersion": "1.6"`; `components` lists the module dependencies with GOST
properties and VCS external references set.

> An alternative to the positional name: `dk sbom get --tag <content-based-tag>`
> or `--digest sha256:...` (mutually exclusive, require `--repo`).

The module developer has no merge/validate operations — that is the next role's
responsibility.

## SBOM owner flow

You are responsible for the product SBOM as a whole. You do not build images —
you work with the per-image SBOMs that module developers have already published
to the registry. Your task is to aggregate them into a single SBOM of the
required granularity (a module, a slice of the product, the whole product) and
validate it against the ISPRAS schemas.

### Prerequisites

- **read access to the container registry** where the images and per-image
  SBOMs live;
- **digests of the images** that make up the product. How to obtain them depends
  on your process: CI artifacts, the build report, or the module developers.
  `sbom merge` accepts **digests, not tags**;
- merge produces SBOMs in the ISPRAS formats only: `oss` or `container`.

### Step 1. Compose `images_digests.json`

|  |  |
|---|---|
| **Input** | digests of the images that make up the product |
| **What to do** | compose a JSON mapping `image name → digest` |
| **Output** | `images_digests.json` |

```json
{
  "<image>": "sha256:<digest>",
  "<another-image>": "sha256:<digest>"
}
```

The values must be valid OCI digests (`sha256:<hex>`), otherwise merge fails
with a parsing error. The set of images defines the granularity of the future
SBOM: a single module, a slice of the product, or the whole product — it is up
to you.

One way to obtain the digests is the build report
(`dk build --save-build-report`), the `.Images.<image>.DockerImageDigest`
field.

### Step 2. Assemble the merged SBOM: `dk sbom merge`

|  |  |
|---|---|
| **Input** | the `images_digests.json` from step 1 |
| **Command** | `dk sbom merge --input=... --ispras-format=... --app-name=... --app-version=... --manufacturer=... -o <file>` |
| **Output** | a single SBOM in an ISPRAS format |

```bash
dk sbom merge \
  --input=images_digests.json \
  --ispras-format=container \
  --app-name=<app> \
  --app-version=<version> \
  --manufacturer=<manufacturer> \
  -o merged-sbom.json
```

`sbom merge` downloads the per-image SBOMs of all images from `--input` by their
digests and merges them into a single SBOM following the ISPRAS schema. Required
flags: `--input`, `--ispras-format` (`oss` | `container`), `--app-name`,
`--app-version`, `--manufacturer`. The `-o` flag is optional — without it the
merged SBOM is printed to stdout.

**Expected result:** a single SBOM in the chosen ISPRAS format that includes the
components of all images from `--input`.

### Step 3. Validate: `dk sbom validate`

|  |  |
|---|---|
| **Input** | the merged SBOM from step 2 (or any local SBOM file) |
| **Command** | `dk sbom validate --path=... --ispras-format=...` |
| **Output** | the result of validation against the ISPRAS schemas |

```bash
dk sbom validate --path=merged-sbom.json --ispras-format=container
```

**Expected result:** validation succeeds (exit code 0). If the SBOM does not
match the schema, the command returns an error describing the problem.
Additionally, `--check-vcs` verifies VCS external references; `--path` can be
repeated to validate several files in one run.

The flow is complete: you have a validated merged SBOM of the product.
