---
title: Signing files inside the image
permalink: usage/build/signing_files.html
---

The `sign` directive of a Stapel image signs files the image produces — a dm-verity root hash, a firmware blob, a release archive — and puts a detached signature next to each of them as `<path>.p7s`. The private key never enters a build container: werf reads the file out of the image, signs it on the build host and adds the signature as a new layer.

Use it when:

- an image ships a file whose consumer checks a signature, for example a dm-verity root hash checked by systemd or the Linux kernel;
- the signing key lives in a KMS (Vault Transit) and the build containers must not receive its credentials;
- [SBOM]({{ "/usage/build/sbom.html" | true_relative_url }}) is enabled, so shell stages run without network and cannot reach the KMS themselves.

The full list of options is in the [reference section]({{ "/usage/build/stapel/imports.html#signing-files-inside-the-image" | true_relative_url }}). This page walks through setting signing up end to end.

## How it works

1. You list the files to sign in `werf.yaml` and, for each of them, the point of the build where it is complete.
2. At that point werf adds a sign stage. The stage reads the file out of the image built so far, signs it with the key passed on the command line and writes `<path>.p7s` next to it.
3. The stage container always runs with `network: none`, and none of the image's commands run in it.
4. The stages that follow, and the images that import from this one, see the file together with its signature.

The signature is a detached PKCS#7 (CMS) `SignedData`: SHA-256, RSASSA-PKCS1-v1_5, no authenticated attributes, the signing certificate embedded. This is the shape `systemd-keyutil pkcs7` produces, so systemd and the Linux kernel accept it as a dm-verity root hash signature.

## Prerequisites

- **An RSA key.** Either a Vault Transit key of an RSA type or a local key file. Other key types are rejected. A local key file must be an encrypted PEM with an empty passphrase (`ENCRYPTED DELIVERY-KIT PRIVATE KEY`); a plain OpenSSL key fails with `decrypt: ...`. One way to convert an existing RSA key is cosign:

  ```shell
  COSIGN_PASSWORD="" cosign import-key-pair --key rsa.pem --output-key-prefix files-signing
  sed 's/ENCRYPTED SIGSTORE PRIVATE KEY/ENCRYPTED DELIVERY-KIT PRIVATE KEY/' files-signing.key > files-signing.dk.key
  ```
- **The certificate of that key** (the leaf, PEM). werf does not fetch it from a KMS or a PKI: the pipeline obtains it and passes it as a path or base64. The certificate is public, so it can also be kept in the repository.
- **For Vault Transit, a role allowed to use the key.** werf signs through `<mount>/sign/<key>/sha2-256` and reads the public key from `<mount>/keys/<key>` to check that it matches the certificate, so the policy needs both:

  ```hcl
  path "transit/sign/files-signing/sha2-256" {
    capabilities = ["update"]
  }

  path "transit/keys/files-signing" {
    capabilities = ["read"]
  }
  ```

## Step 1. Declare the files in `werf.yaml`

Add a `sign` list to the image that produces the file:

```yaml
image: sysext
from: registry.example.com/base/ubuntu:22.04
shell:
  install:
  - mkfs.erofs /out/ext.raw /src
  - veritysetup format --root-hash-file=/out/ext.roothash /out/ext.raw /out/ext.verity
  - tr -d ' \n' < /out/ext.roothash > /tmp/roothash && mv /tmp/roothash /out/ext.roothash
sign:
- path: /out/ext.roothash
```

Without `before` and `after` the file is signed at the end of the image, once its filesystem is complete. This is the right choice in most cases: the signature covers exactly what the image ships, and every image that imports from this one gets it.

To sign at a stage boundary instead, set one of `before` or `after` to `install` or `setup`:

| Entry | The file is signed | The `.p7s` is visible in |
|---|---|---|
| no `before`/`after` | at the end of the image | images importing from this one |
| `before: install` | before `install` | `install`, `beforeSetup`, `setup` |
| `after: install` | after `install` | `beforeSetup`, `setup` |
| `before: setup` | before `setup` | `setup` |
| `after: setup` | after `setup` | images importing from this one |

Rules:

- `path` is an absolute path to a regular file that exists in the image at that point. A directory, a relative path or `/` is an error.
- Each `path` appears once in the list.
- `before` and `after` cannot be set together.
- An entry cannot sign the `.p7s` of another entry at the same position. To sign a signature, give the second entry a later position.
- The directive exists only in Stapel images.

## Step 2 (optional). Check the signature during the build

Sign at a stage boundary and verify the signature in the next stage, where a failure is cheap to diagnose:

```yaml
sign:
- path: /out/ext.roothash
  after: install
shell:
  install:
  - generate-roothash > /out/ext.roothash
  setup:
  - openssl smime -verify -inform der -in /out/ext.roothash.p7s -content /out/ext.roothash -noverify -out /dev/null
```

`-noverify` checks the signature over the content but not the certificate chain. To check the chain too, put the CA certificate into the image and pass it with `-CAfile` instead.

## Step 3. Pass the signature to other images

An image that imports a signed file has to import its signature as well:

```yaml
image: installer
from: registry.example.com/base/ubuntu:22.04
import:
- image: sysext
  add: /out
  to: /payload
  after: install
  includePaths:
  - ext.raw
  - ext.verity
  - ext.roothash
  - ext.roothash.p7s
```

With the default position the signature is already in the imported image. With `before`/`after`, the file and its signature are in the image as soon as that position is passed.

## Step 4. Provide the key and the certificate

The key and the certificate are never part of `werf.yaml`. They come from the command line or the environment, separately from `--sign-key`/`--sign-cert` that sign manifests and SBOMs.

With a PEM key:

```shell
export WERF_SIGN_BUILD_FILE_KEY="$PWD/files-signing.dk.key"
export WERF_SIGN_BUILD_FILE_CERT="$PWD/files-signing.pem"
werf build --repo registry.example.com/project
```

With a Vault Transit key and a JWT login, for example from GitLab CI:

```yaml
build:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  variables:
    WERF_SIGN_BUILD_FILE_KEY: hashivault://files-signing
    WERF_SIGN_BUILD_FILE_CERT: ci/files-signing.pem
    WERF_SIGN_BUILD_FILE_VAULT_ADDR: https://vault.example.com
    WERF_SIGN_BUILD_FILE_VAULT_TRANSIT_PATH: transit
    WERF_SIGN_BUILD_FILE_VAULT_AUTH_PATH: gitlab
    WERF_SIGN_BUILD_FILE_VAULT_AUTH_ROLE: files-signer
  script:
  - export WERF_SIGN_BUILD_FILE_VAULT_AUTH_JWT="$VAULT_ID_TOKEN"
  - werf build --repo "$WERF_REPO"
```

If the certificate is issued by Vault PKI, fetch it before the build, for example `vault read -field=certificate pki/cert/<serial> > ci/files-signing.pem`.

How the Vault options combine:

- `--sign-build-file-vault-addr` and `--sign-build-file-vault-transit-path` fall back one by one to `VAULT_ADDR` and `TRANSIT_SECRET_ENGINE_PATH`.
- The authentication is taken as a whole. With `--sign-build-file-vault-auth-jwt`, werf logs in with that JWT, the role from `--sign-build-file-vault-auth-role` and the mount from `--sign-build-file-vault-auth-path` (`jwt` when unset). Each of them can come from its flag or its `WERF_SIGN_BUILD_FILE_VAULT_AUTH_*` variable, but none falls back to the authentication `--sign-key` uses.
- Without a JWT, werf logs in the same way `--sign-key` does, from the environment. A role or a mount without a JWT is an error.

All `sign` entries of a build share this one signer.

## Step 5. Run the other commands

The certificate takes part in the digest of the sign stage, and so in the image tag. Every command that works out the stages of an image with `sign` needs it — not only `build`, but also `converge`, `render`, `plan`, `run`, `compose`, `kube-run`, `export`, `bundle publish`, `lint`, `sbom get`, `stages copy`, `stage image` and `helm get-autogenerated-values`. Without it they fail before any stage runs.

The private key is needed only where a signature is produced, that is, where the sign stage is not in the registry yet. A deploy job that uses images built earlier needs the certificate only:

```shell
export WERF_SIGN_BUILD_FILE_CERT="$PWD/files-signing.pem"
werf converge --require-built-images --repo registry.example.com/project
```

When none of the processed images and none of their dependencies declare `sign`, neither the certificate nor the key is needed.

A declared `sign` is a requirement of the image: there is no option that builds it unsigned.

## Check the result

Take the file and its signature out of the built image and verify them on any host:

```shell
crane export registry.example.com/project:<tag> - | tar -x out/ext.roothash out/ext.roothash.p7s
openssl smime -verify -inform der -in out/ext.roothash.p7s -content out/ext.roothash -CAfile ca.pem -purpose any -out /dev/null
```

`openssl asn1parse -inform der -in out/ext.roothash.p7s` shows the structure: `sha256`, `rsaEncryption`, no signed attributes, one embedded certificate.

## Caching and key rotation

The sign stage is cached like any other. Its digest covers the stages before it, the signed paths, the position, the certificate and the signature format:

- a rebuild with the same inputs and the same certificate reuses the cached signature and sends no signing request. When a key is passed, werf still logs in to Vault and reads the public key at startup to match it against the certificate, so leave the key out of jobs that only use images built earlier;
- a different certificate rebuilds the sign stage and every stage after it, so the image gets a new tag;
- a different JWT, Vault address or key reference does not change the tag.

To rotate the key, pass the new key and its certificate together. A certificate that does not match the key fails the build with `public key in certificate does not match the provided public key`. Images built earlier keep their old signatures.

## Moving signing out of a build stage

If an image signs a file in a shell stage today, by logging in to a KMS from the container:

1. Replace the login and signing commands with a `sign` entry for the file.
2. Move any verification of the `.p7s` to a stage after the signing position (see step 2): the stage that produces the file no longer sees its signature.
3. Remove the secrets and the mounts that only served signing (KMS address, tokens, the KMS client binary) from the image, and the matching `secrets.allowEnvVariables` and `mount.allowFromPaths` entries from `werf-giterminism.yaml` once nothing else uses them.
4. In CI, pass the key, the certificate and the Vault options as in step 4, and the certificate to every other job that runs werf with this `werf.yaml`.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `images <names> declare files to sign: specify the signing certificate with --sign-build-file-cert` | The command processes an image with `sign` and has no certificate. Pass `--sign-build-file-cert`/`WERF_SIGN_BUILD_FILE_CERT`, including to deploy jobs. |
| `image "<name>" declares files to sign and this stage is not built yet: specify the private key with --sign-build-file-key` | The sign stage has to be built and there is no key. Pass the key, or use images built earlier (`--require-built-images`). |
| `read <path> to sign from image "<name>": ...` | The file does not exist at the signing position. Move the entry to a later position or drop `before`/`after`. |
| `... is a directory, a regular file is required` or `not a regular file` | `path` points to a directory or a special file. Sign a regular file. |
| `public key in certificate does not match the provided public key` | The certificate belongs to another key. Pass the certificate of this key. |
| `signing certificate carries a ... public key, only RSA is supported for detached PKCS#7` | The key is not RSA. Use an RSA key. |
| `the signing certificate does not verify the signature the key produced` | The KMS signed with another key or key version than the certificate describes. Check the key name and the certificate. |
| `--sign-build-file-vault-auth-role and --sign-build-file-vault-auth-path qualify --sign-build-file-vault-auth-jwt: ...` | A role or a mount is set without a JWT. Pass the JWT as well, or drop them. |
| Vault `permission denied` on `<mount>/keys/<key>` or `<mount>/sign/<key>/sha2-256` | The role policy lacks `read` on the key or `update` on signing. See the prerequisites. |
| `specify only one stage using ...`, `duplicated ... for sign!`, `conflicting ... for sign: ...` | The `sign` list breaks one of the rules of step 1. |

## Limitations

- Only Stapel images; the positions are the boundaries of `install` and `setup`, and the end of the image.
- Only RSA keys, SHA-256 and a detached PKCS#7 signature in a separate `<path>.p7s`. A signature embedded into the file itself is not produced.
- One signer per build for all `sign` entries.
- Only the signing certificate is embedded; `--sign-build-file-intermediates` does not take part in the signature or in the digest.
