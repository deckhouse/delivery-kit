---
title: VEX
permalink: usage/build/vex.html
---

[VEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) is a document that states, for a given product, whether it is affected by particular vulnerabilities: a CVE reported by a scanner in a component of the image may not be exploitable because the vulnerable code is never executed, is mitigated by the configuration, or has already been fixed. werf attaches such a document to a built image as an OCI artifact, next to the [SBOM]({{ "/usage/build/sbom.html" | true_relative_url }}), so that vulnerability scanners and audit tooling can read both from the registry.

A VEX document is **attached per image** with the `vex` directive in `werf.yaml`. werf does not generate VEX statements: the document is written by the image maintainer, committed to the Git repository, and published together with the image. Publishing is independent of SBOM generation: an image may carry a VEX document with or without `build.sbom.enable: true`.

## Configuration in `werf.yaml`

The `vex` directive is available for both Dockerfile and Stapel images. The value is a path to an [OpenVEX](https://github.com/openvex/spec) JSON document, relative to the project directory, in either the short or the long form:

```yaml
project: my-project
configVersion: 1
---
image: app
dockerfile: Dockerfile
vex: vex/app.openvex.json
---
image: worker
from: registry.werf.io/werf/scratch:latest
git:
  - add: /
    to: /app
    excludePaths:
      - vex
vex:
  document: vex/worker.openvex.json
```

The two forms are equivalent; an empty value is rejected:

```
`vex` directive must specify a VEX document path, use `vex: PATH` or `vex:
  document: PATH`
```

### Document requirements

The document is read and validated while `werf.yaml` is being parsed, so a broken document fails every command that reads the configuration, not only `werf build`. The document must:

- exist and be a regular file at the given path;
- be valid JSON;
- be a JSON object with `"@context": "https://openvex.dev/ns/v0.2.0"` — the OpenVEX context, matched exactly.

Otherwise the configuration fails with one of:

```
unable to read VEX file "vex/app.openvex.json": ...
invalid VEX document "vex/app.openvex.json": VEX document is not valid JSON
invalid VEX document "vex/app.openvex.json": VEX document has unexpected @context "...", expected "https://openvex.dev/ns/v0.2.0"
```

A minimal document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/app-2024-06-01",
  "author": "Security team <security@example.com>",
  "timestamp": "2024-06-01T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2024-12345"},
      "products": [{"@id": "pkg:oci/app"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable function is never called in this build."
    }
  ]
}
```

werf checks only that the document is JSON with the OpenVEX `@context`; the rest of the document — the presence and content of `statements`, `status`, `justification`, `products` — is not validated and is the responsibility of the author and of the tools that consume the document.

### Giterminism

Like `werf.yaml` itself, the VEX document is read from the current commit: an uncommitted or untracked document fails the build in the usual giterminism way. For development, the `--dev` flag works as for any other file. To permanently allow reading certain VEX documents from the working tree, list them in `werf-giterminism.yaml`:

```yaml
giterminismConfigVersion: 1
config:
  vex:
    allowUncommitted:
      - vex/*.openvex.json
```

See [giterminism]({{ "/usage/project_configuration/giterminism.html#vex" | true_relative_url }}) for the implications.

## Publishing

The VEX artifact is published by `werf build` (and by every command that runs the build conveyor, such as `werf converge`) after the image and its stages have been pushed, right after the SBOM step. It is stored **only in the container registry**: when the build uses local storage (no `--repo`), the VEX step is skipped and nothing is published.

For every image with a `vex` directive the log shows one of:

```
image app: Published VEX artifact
image app: VEX artifact is up to date — skipping publish
```

The artifact is published to the stages repository (`--repo`) and copied from there to the final repository (`--final-repo`) together with the image. For a single-platform image it is also copied to the cache repositories (`--cache-repo`); the VEX artifact of a multi-platform image is attached to the image index, which never exists in a cache repository, so it is not copied there. Secondary repositories (`--secondary-repo`) are read-only and receive nothing. The copy runs on every build, so a destination holding the image without its artifacts is repaired by the next run.

With `--check-built-images` nothing is published, including VEX artifacts: the command only validates that the images already exist. `--require-built-images` (`-Z`) is not a check mode: it publishes previously built images without running build instructions, and the VEX step runs as in an ordinary build.

### Multi-platform images

Unlike the SBOM, which is produced per platform, the VEX document describes the image as a whole. For a multi-platform image werf publishes **one** VEX artifact attached to the image index digest, not to the per-platform manifests. For this reason `--platform` is rejected by `werf attest get` and `werf attest verify` with `--type openvex` when the reference is an index.

## How the VEX artifact is stored

The VEX artifact is stored as an OCI artifact whose subject is the manifest (or index) of the target image, in the same way as the [SBOM]({{ "/usage/build/sbom.html#how-the-sbom-is-stored" | true_relative_url }}): werf maintains a tag-based index that works with any registry and additionally sets the OCI `subject` field for tools that understand the OCI referrers API.

### Artifact structure

The OpenVEX document is wrapped in an [in-toto](https://in-toto.io/) statement and then in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope. The form of the artifact depends on whether the build was signed:

| | Unsigned build | Signed build (`--sign-key`) |
|---|---|---|
| Layer media type | `application/vnd.dsse.envelope.v1+json` | `application/vnd.dev.sigstore.bundle.v0.3+json` (Sigstore bundle containing the signed DSSE envelope and a hint of the public key) |
| in-toto predicate type | `https://openvex.dev/ns/v0.2.0` | `https://openvex.dev/ns` |

The signed form uses the unversioned predicate URI because that is what cosign resolves the `openvex` well-known type to, so a signed VEX artifact is verifiable with stock cosign as well as with `werf attest verify`. Both URIs denote the same kind of artifact: `werf attest get --type openvex` finds either.

werf keeps exactly one build-published VEX artifact per image: publishing a signed artifact replaces the unsigned one and vice versa, so a reader never gets a stale artifact of the previous signing state. An attestation attached by hand with `werf attest sign` is kept separately from the build-published one (werf recognizes its own artifacts by the `io.werf.checksum` annotation), and `werf attest get` / `werf attest verify` prefer the hand-attached one when both exist.

### Artifact annotations

Each VEX artifact carries the following annotations on its descriptor in the index:

| Annotation | Contents |
|---|---|
| `io.werf.image-name` | Name of the image this VEX document belongs to |
| `io.werf.checksum` | Cache identity of the artifact (see [Caching and rebuilds](#caching-and-rebuilds)) |
| `io.werf.target-platform` | Target platform of a single-platform image (e.g. `linux/amd64`) |
| `dev.sigstore.bundle.predicateType` | The in-toto predicate type, so that the kind can be recognized without downloading the layer |

## VEX signing

VEX signing uses the same flags as [SBOM signing]({{ "/usage/build/sbom.html#sbom-signing" | true_relative_url }}) and is enabled by passing a signing key to `werf build`:

| Flag | Environment variable | Purpose |
|---|---|---|
| `--sign-key` | `WERF_SIGN_KEY` | the private key: a path to a PEM file, a base64-encoded PEM, or `hashivault://[KEY]` |
| `--sign-cert` | `WERF_SIGN_CERT` | the leaf certificate: a path to a PEM file or a base64-encoded PEM |
| `--sign-intermediates` | `WERF_SIGN_INTERMEDIATES` | the intermediate certificates: a path to a PEM file or a base64-encoded PEM |

If `--sign-key` is not provided, the VEX document is published unsigned — this is not an error. The same key signs the SBOM and the VEX artifact in one build.

To verify the signature, use `werf attest verify --type openvex` with the public key (`--key`), see below.

## Caching and rebuilds

The `vex` directive and the content of the document **do not take part in stage digests**: adding, changing or removing a VEX document does not rebuild the image by itself. Only the artifact is affected. This holds as long as the document is not part of the build context: a VEX file under a `git` mapping of a Stapel image or copied by a Dockerfile `COPY`/`ADD` is ordinary image content, and editing it rebuilds the image like any other file — keep the document outside the paths that go into the image (see `excludePaths` in the example above).

Whether the artifact is republished is decided by its checksum (`io.werf.checksum`), computed from the document content, the digest of the image it is attached to, the fingerprint of the signing key (empty for an unsigned build) and the artifact format version. A build republishes the artifact when any of these differs from the one already in the registry, and skips the publish otherwise. In practice this means:

- editing the document and rebuilding publishes the new statements under the same image digest — the usual way to react to a newly reported CVE without rebuilding the image;
- enabling signing, rotating the key, or dropping signing republishes the artifact;
- a rebuild with no changes reports `VEX artifact is up to date — skipping publish`.

A VEX artifact exists only for images built after the `vex` directive was added — previously built images have none until the next build with `--repo`.

## Working with VEX attestations

VEX documents are handled by the generic attestation commands of the [`werf attest`]({{ "/reference/cli/werf_attest_get.html" | true_relative_url }}) group. All of them read the registry, so `--repo` is required, and the image is identified with `--tag` or `--digest` (mutually exclusive); `--image` narrows the lookup to one image name when several images share a digest.

[`werf attest ls`]({{ "/reference/cli/werf_attest_ls.html" | true_relative_url }}) lists the attestations attached to the image with their predicate type, digest and whether they are signed. For a multi-platform image the SBOMs are listed under their platforms and the VEX document, attached to the index itself, under the platform `index`; with `--platform` only that platform's attestations are listed, without the index-level ones:

```shell
werf attest ls --repo registry.example.com/project --tag app-1.2.3
```

[`werf attest get`]({{ "/reference/cli/werf_attest_get.html" | true_relative_url }}) downloads the attestation, unwraps the DSSE envelope and the in-toto statement, and prints the OpenVEX document to stdout **without** verifying the signature:

```shell
werf attest get --type openvex --repo registry.example.com/project --tag app-1.2.3 > app.openvex.json
```

[`werf attest verify`]({{ "/reference/cli/werf_attest_verify.html" | true_relative_url }}) does the same after verifying the DSSE signature against one or more public keys (`--key`, repeatable, any match succeeds); an unsigned or badly signed artifact fails the command and prints nothing:

```shell
werf attest verify --type openvex --key vex-signer.pub --repo registry.example.com/project --digest sha256:...
```

[`werf attest sign`]({{ "/reference/cli/werf_attest_sign.html" | true_relative_url }}) signs an arbitrary predicate file (`--predicate`) with `--sign-key` and attaches it to an image. It does not replace the build-published VEX artifact and is not replaced by the next build; while both exist, `werf attest get` and `werf attest verify` return the hand-attached one. To update the VEX statements of an image, edit the document in Git and rebuild instead.

`--type` accepts the well-known names `openvex`, `cyclonedx`, `slsaprovenance`, `slsaprovenance1`, `spdxjson`, or a full predicate URI.
