---
title: VEX
permalink: usage/build/vex.html
---

A vulnerability scanner reports every CVE it can match against the packages in an image — including the ones that do not matter for this particular image: the vulnerable function is never called, the affected feature is disabled by configuration, or the fix has been backported under the same package version. [VEX](https://openvex.dev/) (Vulnerability Exploitability eXchange) is the standard way to record such verdicts so that scanners and audit tooling stop raising them.

werf lets you keep a VEX document next to the image it describes: declare it in `werf.yaml`, and `werf build` publishes it to the container registry as an attestation of the image — signed with the same key as the [SBOM]({{ "/usage/build/sbom.html" | true_relative_url }}) when signing is on. Anyone who has the image can fetch the verdicts, check who signed them, and feed them into their scanner.

werf does not write VEX statements for you: deciding that a CVE does not apply is a security judgment made by the image maintainer, and the document is maintained in Git like the rest of the configuration.

## Quick start

1. Write an [OpenVEX](https://github.com/openvex/spec) document, e.g. `vex/app.openvex.json`. The product is the image as the scanner sees it — the repository it is published to, not the `image:` name from `werf.yaml` (see [Using the verdicts in a scan](#using-the-verdicts-in-a-scan) for the details):

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
         "products": [{"@id": "pkg:oci/project?repository_url=registry.example.com/project"}],
         "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path",
         "impact_statement": "The vulnerable function is never called in this build."
       }
     ]
   }
   ```

2. Point the image at it in `werf.yaml` — the path is relative to the project directory and the directive works for Dockerfile and Stapel images alike — and commit both files, as giterminism reads them from the commit:

   ```yaml
   image: app
   dockerfile: Dockerfile
   vex: vex/app.openvex.json
   ```

   ```shell
   git add werf.yaml vex/app.openvex.json && git commit -m "Add VEX for app"
   ```

3. Build with a registry, tagging the image so that it can be referred to afterwards. If your builds sign SBOMs or manifests, keep passing the same `--sign-key` — the VEX document is signed with it too:

   ```shell
   werf build --repo registry.example.com/project --add-custom-tag '%image%-1.2.3' [--sign-key KEY]
   ```

   The log confirms the publish for every image that has a document:

   ```
   image app: Published VEX artifact
   ```

   Without `--sign-key` the document is published **unsigned**: anyone with push access to the repository could replace it. Consumers who must be able to trust the verdicts verify the signature with `werf attest verify` instead of `get` below; see [Trusting the verdicts](#trusting-the-verdicts).

4. Check that the document is attached to the image:

   ```shell
   werf attest get --type openvex --repo registry.example.com/project --tag app-1.2.3
   ```

   The command prints the document you committed.

## Working with VEX day to day

### A scanner reports a CVE that does not apply

Confirm the verdict, then add a statement to the image's document: the CVE id exactly as the scanner reports it (`vulnerability.name`), the image as the product, `status: not_affected` with one of the five OpenVEX justifications — `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist` (see the [specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications) for their meaning) — and an `impact_statement` explaining the reasoning for the reader who comes after you. If only a specific package is concerned, narrow the statement with `subcomponents` (the package's PURL); a statement without `subcomponents` applies to every occurrence of that CVE in the image.

A CVE that is actually fixed in your build — a backported patch, for instance — is recorded with `status: fixed`. Scanners treat both `not_affected` and `fixed` as "do not report". To withdraw a verdict, change the statement's `status` to `affected` (or remove the statement) — the scanner reports the CVE again.

When you change the document, bump its `version` and refresh `timestamp`: werf does not require it (it republishes whenever the file content differs), but OpenVEX consumers use them to order documents about the same product. The document `@id` is an identifier, not a URL that has to resolve — any IRI unique to your organization will do.

Commit the document and run `werf build` again with the same flags as before. **The image is not rebuilt**: the `vex` directive and the document content do not take part in stage digests, so the build only republishes the attestation against the same image digest. Keep the document outside the paths that go into the image — a VEX file under a Stapel `git` mapping or copied by a Dockerfile `COPY` is ordinary image content, and editing it rebuilds the image like any other file.

### Using the verdicts in a scan

Fetch the document from the registry and hand it to the scanner. With [Trivy](https://trivy.dev/latest/docs/supply-chain/vex/file/):

```shell
werf attest get --type openvex --repo registry.example.com/project --tag app-1.2.3 > app.openvex.json
trivy image --vex app.openvex.json registry.example.com/project:app-1.2.3
```

Findings covered by a `not_affected` or `fixed` statement are dropped from the report; `--show-suppressed` lists them with the statement that suppressed each one.

A statement applies when both the vulnerability id and the product match. For a container image Trivy expects the product as a `pkg:oci` PURL: the repository the scanner pulls the image from goes into `repository_url` — `--final-repo` when you use one, since that is what gets scanned and deployed, otherwise `--repo` — its last path segment is the name, and the image digest is optional:

```
pkg:oci/project?repository_url=registry.example.com/project                  # every image in the repository
pkg:oci/project@sha256:<digest>?repository_url=registry.example.com/project  # one image digest
```

Note that the name is taken from the repository, not from `image:` in `werf.yaml`, and werf publishes all images of a project into one repository. A product without a digest therefore covers every image of the project — fine while each image has its own document with its own statements, since the scanner only sees the document you hand it. To bind a statement to one image regardless of which document is used, pin the digest; after the build it is in the [build report]({{ "/usage/build/process.html#build-report" | true_relative_url }}) (`werf build --save-build-report`, field `Images.<name>.DockerImageDigest`), and for a multi-platform image this is the digest of the image index. Since the digest changes with every rebuild of the image, pinning is best reserved for verdicts that are tied to one specific build.

To limit a statement to one package, add its PURL as a subcomponent of the product — take it from the Trivy JSON report (`trivy image -f json …`, the `PkgIdentifier.PURL` field of the finding):

```json
"products": [{
  "@id": "pkg:oci/project?repository_url=registry.example.com/project",
  "subcomponents": [{"@id": "pkg:deb/debian/openssl"}]
}]
```

If a CVE is still reported after the document is applied, compare three things with the JSON report: the vulnerability id (`VulnerabilityID`), the product PURL (repository and, if you pinned it, the digest of the image being scanned), and the package PURL in `subcomponents`. The matching rules are described on the Trivy [Local VEX files](https://trivy.dev/latest/docs/supply-chain/vex/file/) and [OCI VEX](https://trivy.dev/latest/docs/supply-chain/vex/oci/) pages.

### Trusting the verdicts

When the build was signed (`--sign-key`), the attestation carries a signature, and a consumer can refuse unsigned or tampered verdicts:

```shell
werf attest verify --type openvex --key vex-signer.pub \
  --repo registry.example.com/project --tag app-1.2.3 > app.openvex.json
```

`werf attest verify` prints the document only after the signature checks against one of the given public keys (`--key` may be repeated); an unsigned or badly signed attestation fails the command and prints nothing. `werf attest get` prints the document without verifying it.

A consumer without werf can verify the same attestation with stock [cosign](https://github.com/sigstore/cosign) (v2.5 or later), fully offline — the attestation is a standard Sigstore bundle and werf's key-based signatures are not recorded in a transparency log, hence the trusted root without services and `--insecure-ignore-tlog`:

```shell
cosign trusted-root create --out trusted-root.json
cosign verify-attestation --new-bundle-format --trusted-root trusted-root.json --insecure-ignore-tlog=true \
  --key vex-signer.pub --type openvex registry.example.com/project@sha256:<digest>
```

For a multi-platform image `<digest>` is the digest of the image index.

Signing uses the same flags and key material as [SBOM signing]({{ "/usage/build/sbom.html#sbom-signing" | true_relative_url }}): `--sign-key` / `WERF_SIGN_KEY` (a PEM file, a base64-encoded PEM, or `hashivault://[KEY]`), optionally `--sign-cert` and `--sign-intermediates`. Without `--sign-key` the document is published unsigned — this is not an error. Turning signing on, rotating the key, or turning it off republishes the attestation on the next build without rebuilding the image.

### Listing what is attached to an image

```shell
werf attest ls --repo registry.example.com/project --tag app-1.2.3
```

shows every attestation of the image — SBOMs per platform and the VEX document — with its predicate type, digest and whether it is signed:

```
PLATFORM     PREDICATE TYPE             DIGEST                  SIGNED
linux/amd64  https://cyclonedx.org/bom  sha256:3f1c9a0b2d4e...  yes
linux/arm64  https://cyclonedx.org/bom  sha256:8e7d6c5b4a39...  yes
index        https://openvex.dev/ns     sha256:a1b2c3d4e5f6...  yes
```

For a multi-platform image the VEX document is listed under the platform `index`, because it describes the image as a whole and is attached to the image index rather than to a platform manifest; `--platform OS/ARCH` lists that platform's attestations only.

## What to expect

- **A registry is required.** The attestation lives only in the container registry. With local stages storage (no `--repo`) the VEX step is skipped silently and nothing is published.
- **Where it ends up.** The attestation is published to `--repo` and copied to `--final-repo` together with the image. For a single-platform image it is copied to `--cache-repo` as well; the VEX of a multi-platform image is attached to the image index, which cache repositories never hold, so it is not copied there. `--secondary-repo` is read-only. The copy runs on every build, so a destination holding the image without its attestations is repaired by the next run.
- **Multi-platform images get one document.** Unlike the SBOM, which is produced per platform, one VEX attestation is attached to the image index. `werf attest get` and `werf attest verify` take the index reference; `--platform` is rejected for `--type openvex` on an index.
- **Previously built images have none.** A VEX attestation exists for images built after the `vex` directive was added — until the next `werf build --repo`, older images carry no document. The reverse also holds: removing the `vex` directive stops publishing but does not detach what is already in the registry — an image digest that received a document keeps it. To withdraw verdicts from an image that stays in use, publish a document whose statements say `affected` instead.
- **Unchanged document, unchanged image → nothing happens.** The build reports `VEX artifact is up to date — skipping publish`. Republishing is triggered by a change in the document, in the image digest, or in the signing key.
- **`--check-built-images` publishes nothing**, VEX included; it only validates that images exist. `--require-built-images` (`-Z`) is not a check mode: it publishes previously built images and runs the VEX step as an ordinary build does.
- **Hand-attached attestations take precedence.** An attestation attached with `werf attest sign` is kept apart from the build-published one: the build does not replace it, and while both exist `werf attest get` and `werf attest verify` return the hand-attached one. Editing the document in Git and rebuilding updates only the build-published attestation — if an image has a hand-attached VEX, update it with `werf attest sign` as well, or do not attach VEX by hand to images that carry one from the build. There is no command to detach an attestation; the practical way back is to rebuild the image under a new digest, which starts with no hand-attached attestations.

### Validation errors

The document is read and validated while `werf.yaml` is parsed, so a broken document fails every werf command that reads the configuration, not only `werf build`. werf requires the file to exist, to be JSON, and to carry the OpenVEX context exactly — `"@context": "https://openvex.dev/ns/v0.2.0"`; it does not validate the statements themselves.

```
`vex` directive must specify a VEX document path, use `vex: PATH` or `vex:
  document: PATH`
unable to read VEX file "vex/app.openvex.json": ...
invalid VEX document "vex/app.openvex.json": VEX document is not valid JSON
invalid VEX document "vex/app.openvex.json": VEX document has unexpected @context "...", expected "https://openvex.dev/ns/v0.2.0"
```

### Giterminism

Like `werf.yaml` itself, the VEX document is read from the current commit: an uncommitted or untracked document fails the build in the usual giterminism way, and `--dev` works as for any other file. To permanently allow reading certain documents from the working tree, list them in `werf-giterminism.yaml`:

```yaml
giterminismConfigVersion: 1
config:
  vex:
    allowUncommitted:
      - vex/*.openvex.json
```

See [giterminism]({{ "/usage/project_configuration/giterminism.html#vex" | true_relative_url }}) for the implications.

## Reference

### `werf.yaml`

```yaml
vex: PATH
# or
vex:
  document: PATH
```

The two forms are equivalent. `PATH` is relative to the project directory. The directive is accepted on Dockerfile and Stapel images.

### Storage layout

The attestation is stored as an OCI artifact whose subject is the manifest (or the index) of the image, in the same way as the [SBOM]({{ "/usage/build/sbom.html#how-the-sbom-is-stored" | true_relative_url }}): werf maintains a tag-based index that works with any registry and additionally sets the OCI `subject` field for tools that understand the OCI referrers API.

The OpenVEX document is wrapped in an [in-toto](https://in-toto.io/) statement and then in a [DSSE](https://github.com/secure-systems-lab/dsse) envelope:

| | Unsigned build | Signed build (`--sign-key`) |
|---|---|---|
| Layer media type | `application/vnd.dsse.envelope.v1+json` | `application/vnd.dev.sigstore.bundle.v0.3+json` — a Sigstore bundle with the signed DSSE envelope and a hint of the public key |
| in-toto predicate type | `https://openvex.dev/ns/v0.2.0` | `https://openvex.dev/ns` |

The signed form uses the unversioned predicate URI because that is what cosign resolves the `openvex` type to, so a signed attestation is verifiable with stock cosign as well. Both URIs denote the same kind of attestation and `--type openvex` finds either. Exactly one build-published VEX attestation is kept per image: a signed one replaces the unsigned one and vice versa. werf recognizes its own attestations by the `io.werf.checksum` annotation, computed from the document content, the digest of the image, the signing key fingerprint and the artifact format version — this is what decides whether a build republishes.

### `werf attest`

`--repo` is required by every subcommand; the image is identified with `--tag` or `--digest` (mutually exclusive), and `--image` narrows the lookup to one image name when several images share a digest. `--type` accepts `openvex`, `cyclonedx`, `slsaprovenance`, `slsaprovenance1`, `spdxjson`, or a full predicate URI.

- [`werf attest get`]({{ "/reference/cli/werf_attest_get.html" | true_relative_url }}) — print the document without verifying the signature.
- [`werf attest verify`]({{ "/reference/cli/werf_attest_verify.html" | true_relative_url }}) — verify the signature with `--key` (repeatable), then print the document.
- [`werf attest ls`]({{ "/reference/cli/werf_attest_ls.html" | true_relative_url }}) — list the attestations of an image.
- [`werf attest sign`]({{ "/reference/cli/werf_attest_sign.html" | true_relative_url }}) — sign an arbitrary predicate file (`--predicate`, `--type`) with a plain PEM `--sign-key` and attach it to an image.
