---
title: Importing from images
permalink: usage/build/stapel/imports.html
author: Alexey Igrychev <alexey.igrychev@flant.com>
directive_summary: import
---

The size of the final image can grow dramatically due to the assembly tools and source files eating up space. These files are generally not needed in the final image.
To avoid this, the Docker community suggests installing tools, building, and removing irrelevant files in one step:

```Dockerfile
RUN “download-source && cmd && cmd2 && remove-source”
```

> You can do the same in werf — just specify the relevant instructions for some _user stage_. Below is an example of specifying the _shell assembly instructions_ for the _install stage_:
```yaml
shell:
  install:
  - "download-source"
  - "cmd"
  - "cmd2"
  - "remove-source"
```

However, this method does not support caching. Thus, a build toolkit will be installed all over again.

Another way is to use a multi-stage build, a feature supported in Docker since version 17.05:

```Dockerfile
FROM node:latest AS storefront
WORKDIR /app
COPY react-app .
RUN npm install
RUN npm run build

FROM maven:latest AS appserver
WORKDIR /app
COPY . .
RUN mvn package

FROM java:8-jdk-alpine
COPY --from=storefront /app/react-app/build/ /static
COPY --from=appserver /app/target/AtSea-0.0.1-SNAPSHOT.jar /app/AtSea.jar
```

The point of this approach is to describe several auxiliary images and selectively copy artifacts from one image to another, leaving all the unnecessary data outside the final image.

werf offers the same approach.

> Why doesn't werf use multi-stage assembly?
* Historically, _imports_ came much earlier than the Docker multi-stage mechanism, and
* werf allows for greater flexibility when working with auxiliary images.

## Import configuration

Importing _resources_ from the _images_ must be described in the `import` directive in the _destination image_ in the _image_ config section. `import` is an array of records, where each record must contain the following:

- `from: <image name>`: _source image_; the name of the image copy files from. Both imports from images of the current project and from external images in the format `image_name:tag` or `image_name@digest` are supported.
- `add: <absolute path>`: _source path_; the absolute path to the file or directory in the _source image_ to copy from.
- `to: <absolute path>`: _destination path_; the absolute path in the _destination image_. If absent, the _destination path_ defaults to the  _source path_ (as specified by the `add` directive).
- `before: <install || setup>` or `after: <install || setup>`: _destination image stage_; the stage to import files. Currently, only _install_ and _setup_ stages are supported.

An example of the `import` directive:

```yaml
import:
  - from: application-assets
    add: /app/public/assets
    to: /var/www/site/assets
    after: install
  - from: node:20-alpine
    add: /usr/share/nginx/html
    to: /var/www/site/prebuilt
    after: setup
```

As with the _git mappings_ configuration, include and exclude file and directory masks are supported (`includePaths: []` and `excludePaths: []`, respectively). Masks must be specified relative to the source path (as in the `add` parameter).
You can also specify an owner and a group for the imported resources, `owner: <owner>` and `group: <group>`.
This behavior is similar to the one used when adding code from Git repositories, and you can read more about it in the [git directive section]({{ "usage/build/stapel/git.html" | true_relative_url }}).

> Note that the path of imported resources and the path specified in _git mappings_ must not overlap.

### Destination path rules

What ends up at the _destination path_ depends on whether the _source path_ is a directory or a file.

If `add` is a **directory**, its contents are merged into `to`. Files already present in `to` are kept, and files with the same name are overwritten. This is why several imports may target the same directory.

If `add` is a **file**, the outcome depends on the _destination image_:

- if `to` does not exist, the file is created at exactly that path — `add: /app/config.yaml` with `to: /etc/app.yaml` produces `/etc/app.yaml`;
- if `to` already exists as a directory, the file is placed inside it — the same import with `to: /etc` produces `/etc/config.yaml`.

werf creates only the parent directory of `to`, so whether `to` itself exists is decided by the _destination image_ — pin the full file path when the difference matters.

A trailing slash in `to` (anything other than `to: /`) is a configuration error and fails the build: write `to: /usr/sbin`, not `to: /usr/sbin/`.

## Signing files inside the image

The `sign` directive signs a file the image produces and lays the signature down next to it, without giving the build stage access to the signing key.

With neither `before` nor `after`, the file is signed at the end of the image, once its filesystem is complete — that is what a signed artifact of the image usually means, and it is what another image importing the result gets. Naming a stage puts the signature earlier: it fits the same place in the stage chain as `import`, the file must exist after the stage named by `before` or `after`, and the signature is in place for the stages that follow. Setting both is a configuration error.

```yaml
image: sysext
from: registry.example.com/base/ubuntu:22.04
shell:
  install:
  - mkfs.erofs /out/ext.raw /src
  - veritysetup format --root-hash-file=/out/ext.roothash /out/ext.raw /out/ext.verity
sign:
- path: /out/ext.roothash
  after: install
```

`path` may also be a glob pattern (`*`, `?`, `[...]`, `{a,b}`, `**`), expanded against the image filesystem when the signing stage runs: every regular file it matches gets its own `<file>.p7s`. The pattern must start with a literal directory below `/` (`/out/**/*.ko`, not `/**/*.ko`). Below that directory symlinks are neither matched nor followed, so a file is signed under its real path only; a hard link is a regular file under another name and is signed under each. A pattern that matches nothing fails the build — a declared signature is a requirement of the image, not a hint. This is how a set of files known only after the build is signed, such as the kernel modules `make modules_install` produces:

```yaml
sign:
- path: /out/lib/modules/**/*.ko
  after: install
```

Because of this, `*`, `?`, `[` and `{` are metacharacters in `path`: a file whose name contains one of them is written with a backslash before it, `path: /out/file\[1\].bin`, otherwise the entry is expanded as a pattern and signs whatever that pattern matches.

Entries at the same signing position must not use another entry's `<path>.p7s` as an input. For example, `path: /out/x` and `path: /out/x.p7s` at the same position are a configuration error, regardless of their order in the list. The same holds for the files a pattern expands to, and a file reached through two entries is an error as well; both are detected when the pattern is expanded. To sign a generated signature, put the second entry at a later signing position.

werf reads the file out of the image built so far, signs it on the build host and adds `<path>.p7s` as a new layer. The signature is a detached PKCS#7 (CMS) `SignedData` over the file content — SHA-256, RSASSA-PKCS1-v1_5, no authenticated attributes, the signing certificate embedded — the same shape `systemd-keyutil pkcs7` produces, so systemd and the Linux kernel accept it as a dm-verity root hash signature. The key therefore has to be RSA.

The key and the certificate are never part of `werf.yaml`; they come from the command line only, separately from the manifest and SBOM signing identity:

| Flag | Environment variable | Description |
|---|---|---|
| `--sign-build-file-key` | `WERF_SIGN_BUILD_FILE_KEY` | the private key: a path to a PEM file, a base64-encoded PEM, or `hashivault://[KEY]` |
| `--sign-build-file-cert` | `WERF_SIGN_BUILD_FILE_CERT` | the signing certificate: a path to a PEM file or a base64-encoded PEM |
| `--sign-build-file-intermediates` | `WERF_SIGN_BUILD_FILE_INTERMEDIATES` | the intermediate certificates: a path to a PEM file or a base64-encoded PEM |
| `--sign-build-file-vault-addr` | `WERF_SIGN_BUILD_FILE_VAULT_ADDR` | the Vault address a `hashivault://` key is resolved against; unset → `VAULT_ADDR` |
| `--sign-build-file-vault-transit-path` | `WERF_SIGN_BUILD_FILE_VAULT_TRANSIT_PATH` | the transit engine mount of the key; unset → `TRANSIT_SECRET_ENGINE_PATH` |
| `--sign-build-file-vault-auth-jwt` | `WERF_SIGN_BUILD_FILE_VAULT_AUTH_JWT` | the JWT to log in to Vault with; unset → the authentication `--sign-key` uses, from the environment |
| `--sign-build-file-vault-auth-role` | `WERF_SIGN_BUILD_FILE_VAULT_AUTH_ROLE` | the Vault JWT role; qualifies the JWT above and is rejected without it |
| `--sign-build-file-vault-auth-path` | `WERF_SIGN_BUILD_FILE_VAULT_AUTH_PATH` | the JWT auth mount; qualifies the JWT above and is rejected without it; unset → `jwt` |

The `--sign-build-file-vault-*` options exist so that the files signer and the `--sign-key` signer can live in different Vault mounts and log in under different roles within one `werf build`.

The address and the transit mount fall back one by one: either left unset takes what `--sign-key` would use (`VAULT_ADDR`, `TRANSIT_SECRET_ENGINE_PATH`). The authentication does not work that way — it is taken as a whole. With a JWT given, the files signer logs in with that JWT, the role of `--sign-build-file-vault-auth-role` (empty when unset) and the mount of `--sign-build-file-vault-auth-path` (`jwt` when unset); none of the three falls back to the environment. Without a JWT the whole authentication comes from the environment, and a role or a mount passed on their own are rejected. The authentication is validated as soon as werf resolves a declared `sign` — including a command that only has the certificate and never logs in to Vault at all.

There is no way to build such an image unsigned: a declared `sign` is a requirement of the image, not a build-time choice.

The certificate and the private key are needed at different moments. The certificate is the public identity of the signature and takes part in the stage digest, so every command that works out the image's stages asks for it — including `--require-built-images`, which only resolves an already built image. The private key produces the signature and is needed only where a signature is actually produced: resolving, rendering or deploying an image built earlier needs no key and no access to the KMS.

A build of an image that declares `sign` fails before any stage runs when the certificate is missing. Without the private key it fails at the first signature it would have to produce.

With `hashivault://` the private key never leaves the KMS. The certificate is not fetched from the KMS: when it is issued by a PKI (Vault PKI, for example), the pipeline retrieves the PEM itself and passes it as a path or base64. The stage container always runs with `network: none`, whatever the image's `network` setting, and none of the image's commands run in it, so the directive works unchanged when `build.sbom.enable` is `true` and [network is disabled in shell stages]({{ "/usage/build/sbom.html" | true_relative_url }}).

The stage is cached like any other. Its digest covers the signed paths, signing position, signing certificate and signature format. Changing any of these invalidates the sign stage and the stages after it; with unchanged build inputs, the cached layer is reused. The private key reference and Vault authentication settings do not change the cache identity. When rotating the key, supply a matching certificate. Only the signing certificate is embedded in the `.p7s`; intermediates do not take part in the signature or the digest.
