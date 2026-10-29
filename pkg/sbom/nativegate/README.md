# Composition verification

SBOM-enabled Stapel builds use one pipeline: ordinary Go/Python/Node and installed-package evidence is combined with verified original files and embedded native composition. Verification runs before a cached SBOM publication can be reused. Builds without SBOM retain their previous package commands.

`WERF_DK_NATIVE_POLICY` is no longer a production feature switch. The default checks cover every shipped binary/executable. Whole-file UTF-8 text with a recognized shell/Python/Node shebang is routed through ordinary file/language evidence rather than required to carry a native note. This classification does not assert ownership or interpreter availability; unknown formats and raw binary payloads remain strict, and a changed previously-bound foreign executable script is rejected. The explicit `Policy`/`Apply` APIs remain available for the isolated policy fixtures; production uses `NewDefaultPolicy` and `ApplySourceSnapshots`.

The conservative script classifier recognizes `ash`, `bash`, `dash`, `node`, `python`, `python3` and `sh` as the basename of an absolute interpreter path, or through `/usr/bin/env` with optional `-S`. Other interpreter spellings, quoted shebangs and binary control bytes are unsupported. Classification is not a claim that the script is runnable (for example, CRLF text is still text), nor that text cannot encode executable payloads.

## Original files and scope

SBOM-enabled os-pm directives request `--sbom-sources-file /var/lib/pm/sbom-sources.json`. The builder must provide a pm binary supporting that option. Calls writing one receipt are sequential; atomic replacement alone does not make concurrent writers safe.

The shared `sbom/sources` codec carries source candidates, not successful-install claims. DK captures actual base, packages and subsequent stage rootfs snapshots. It resolves pinned originals using the shared `sbom/original` OCI validation API and its filesystem reader, with DK's existing registry transport/authentication. Selected original bytes are verified to EOF in a batched layer walk. Missing data, unknown schemas, invalid receipts and incomplete snapshots are not replaced with `files.json` or current-file hashes.

Import filter semantics are read from the backend recorded in the actual cached stage label, not guessed from the current builder. Older import stages without this evidence fail with `no-data` and require the agreed clean rebuild.

Initial bindings require an original path actually present in the source snapshot. Later shell snapshots can match bytes from the scoped before snapshot; this establishes content correspondence, not proof of a physical move or copy. Imports retain their actual From/To paths and include/exclude rules. A lost import boundary is not permission to search the whole package.

Equal-byte distinct sources remain alternatives. A consumer requiring one original binding reports `no-data` if none can be established. Alternatives are never merged into an invented package owner. Distinct pinned sources of the same package name/version remain distinct through CycloneDX canonicalization.

The current image carries two self-contained metadata properties:

- `dk:catalog/v4`: verified file/native records, raw embedded composition and their component graph.
- `dk:originals/v1`: canonical source candidates with raw Packet JSON and scoped file SHA-256/size/original-path alternatives.

Inherited originals are rechecked against the actual source image and pinned original bytes. Current catalog properties replace inherited ones after the common merge. Scanner-only Go attribution is removed only when its complete binary evidence is superseded by the same verified bytes; independent file-based or unresolved evidence is not silently discarded.

## Compiler context delivery

Generated package jobs can bind checked shell stages to explicit prepared-source dependencies through the private `werf.io/sbom-build-context-v1` image-spec label. It identifies the stage, the subject's package-list index, and each declared source-image handle with expected package name/version/type/original platform. It does not supply a guessed digest or infer ownership from an image alias.

Before a declared stage's cache lookup, DK resolves those earlier imports, checks the actual dependency image's `pkg.*` metadata and manifest digest, and derives physical source mappings from the observed import/stage scope. The canonical `sbom/buildcontext` codec writes Context v1; original OCI layouts and the context are mounted read-only under `/.werf/sbom-build-context`, and DK supplies `SBOM_BUILD_CONTEXT` before compiler execution. Compilers do not fetch originals. The private declaration is removed from published image labels.

Context identity contributes to the stage checksum. Declared images cannot bypass this validation through the image-level cache shortcut; ordinary stage reuse remains available after validation. Scratch paths are not part of the checksum, and the context mount is cleaned up when the stage finishes or fails. Undeclared stages and builds without SBOM receive no compiler context. A declared stage must have earlier source imports; a `beforeInstall` declaration without such an observed dependency is refused rather than inferring sources from the base image.

The subject remains the verified prepared-source package (for example, a source distribution shared by several runtime outputs), not the output image name. This path does not synthesize `ownRoots`, freeze newly generated inputs during a checked stage, or turn unobserved paths into package originals. Preparation/freeze must precede consumption. Original distribution platforms remain distinct from the binary target; cross-target commands require the Go SDK's per-invocation target handling.

## Native records

The shared reader validates embedded records directly from ELF, thin Mach-O and PE bytes. No native composition sidecar or guessed installed-package inventory is accepted as a replacement. Record schema, required tool identities, supported profile/platform/revision, native container shape and available Go buildinfo contradictions are checked by the reader; rootfs interpreter/library closure is checked by DK.

Tool hashes describe the trusted producer's actual executables. DK does not require those compiler/helper bytes in the final image. If a tool is itself shipped, its own composition must pass the same binary checks. Unavailable intermediate object/archive/source hashes remain producer claims. An observed final-file digest is not a final-ELF self-hash guarantee: arbitrary code changes with unchanged valid notes/buildinfo are not detected by the record reader alone. Expected original-byte verification is a separate consumer check.

Supported executable profiles are C-static and C-dynamic on Linux/amd64; pure Go on Linux/amd64 and Linux/ARM; Go Mach-O on Darwin/amd64 and Darwin/arm64; and Go PE on Windows/amd64. Foreign DLL/dylib references are diagnostics, not dependencies resolved against the Linux rootfs. Linux/ARM executables must have no interpreter or dynamic-library dependency; existing Linux/amd64 loader/library closure checks are retained. The Go fixture matrix covers explicit empty dependencies, versioned modules, versioned/local replacement, and tagged/dirty Main metadata. Its SDK originals were synthetic test inputs, not delivered SDK acceptance. CGO, other targets and the full producer/pilot matrix remain separate gates. The frozen cross-CLI fixtures prove record/container/buildinfo agreement for explicit targets, not the effective GOARCH/GOARM settings of an operator recipe.

Non-Stapel images currently fail with `no-data` because this path has no verified stage/import boundary chain for them. This is an open coverage limit, not a claim that Dockerfile builds are outside the required final matrix. Ambiguous intermediate destination type/link changes within a multi-import stage also fail rather than guess where bytes were copied.

## Verification

`task test:native-poc` requires `DK_LOADER_FIXTURE`, `DK_NATIVE_INSPECT_FIXTURE`, `DK_GO_FIXTURE`, `DK_GO_MODULES_FIXTURE`, `DK_CROSS_CLI_FIXTURE` and `DK_PM_BINARY`, checks their frozen hashes, and rejects every skipped or missing spec. It includes serial real-pm install/skip calls, observed shell relocation, scoped import, and JSON read-back. The fixture binaries are not stored in Git.

The ordinary packages-stage command checksum changes when the receipt option is enabled. There is no separate SBOM cache-version tag or migration; the agreed transition is a manual clean rebuild. No cache purge is performed by this code.
