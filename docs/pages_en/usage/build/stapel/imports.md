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

The `sign` directive signs a file the image produces and lays the signature down next to it, without giving the build stage access to the signing key. It fits the same place in the stage chain as `import`: the file must exist after the stage named by `before` or `after`, and the signature is in place for the stages that follow.

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

werf reads the file out of the image built so far, signs it on the build host and adds `<path>.p7s` as a new layer. The signature is a detached PKCS#7 (CMS) `SignedData` over the file content — SHA-256, RSASSA-PKCS1-v1_5, no authenticated attributes, the signing certificate embedded — the same shape `systemd-keyutil pkcs7` produces, so systemd and the Linux kernel accept it as a dm-verity root hash signature. The key therefore has to be RSA.

The key and the certificate are never part of `werf.yaml`; they come from the command line only, separately from the manifest and SBOM signing identity:

| Flag | Environment variable | Description |
|---|---|---|
| `--sign-files` | `WERF_SIGN_FILES` | process `sign` directives (default `true`); `false` skips them and builds the image without the signatures |
| `--sign-files-key` | `WERF_SIGN_FILES_KEY` | the private key: a path to a PEM file, a base64-encoded PEM, or `hashivault://[KEY]` |
| `--sign-files-cert` | `WERF_SIGN_FILES_CERT` | the signing certificate: a path to a PEM file or a base64-encoded PEM |
| `--sign-files-intermediates` | `WERF_SIGN_FILES_INTERMEDIATES` | the intermediate certificates: a path to a PEM file or a base64-encoded PEM |

A build of an image that declares `sign` fails before any stage runs when the key or the certificate is missing and `--sign-files` is not `false`. With `hashivault://` the private key never leaves the KMS: the stage container runs no commands and needs no network, so the directive works unchanged when `build.sbom.enable` is `true` and [network is disabled in shell stages]({{ "/usage/build/sbom.html" | true_relative_url }}).

The stage is cached like any other. Its digest covers the signed paths and the signing certificate chain, so rotating the key rebuilds the signature and the stages after it, while a rebuild with the same key reuses the cached layer.
