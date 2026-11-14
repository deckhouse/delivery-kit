# Increment 1 stand: negative scenarios and one positive build

`increment1_test.go` (label `increment1`) builds the fixtures of `../_fixtures/increment1` with a
Delivery Kit binary against an instrumented stand, and checks that each negative scenario is refused
with the file (or package) named, and the positive one builds. Nothing here builds an image by itself:
the specs skip, naming the missing `WERF_TEST_I1_*` variables, until a stand is configured.

| fixture | scenario | expected refusal (names, reason) |
|---|---|---|
| `pkg-file-replaced` | a file of a pm package changed by a shell stage after installation | `@PM_PACKAGE_FILE@`, `hash-mismatch` |
| `elf-in-git` | an ELF binary from a git mapping (stock Linux `/bin/true`, no instrumented composition) | `/app/tool`, `missing build record` |
| `git-file-edited` | a file of a commit changed by a shell stage | `/app/config.txt`, `hash-mismatch` |
| `package-outside-index` | a pm package whose index is not in `WERF_SBOM_TRUSTED_INDEXES` | `@PM_PACKAGE@`, `outside instrumented index` |
| `base-without-sbom` | a base image that has no instrumented SBOM | `no-data`, `SBOM` |
| `positive` with `--platform=linux/arm64` | a build for a platform the chain does not cover | `linux/arm64`, `platform` |
| `positive` | a C program on `builder/native` and a Go program on `builder/golang-alt-1.27` | builds; `/app/hello` is a file component with `dk:origin=build`; the SBOM carries `dk:verification=instrumented-v1` |

The reasons are the wording of `pkg/sbom/nativegate`. A change of wording changes the table in the test.

## Variables

Set by the stand (take the values from the state file of the track that publishes the chain):

| variable | meaning |
|---|---|
| `WERF_TEST_BINARY_PATH` | the Delivery Kit binary (`dk-build.sh <sha>` writes it to `.../dk-1/releases/<sha>/werf`) |
| `WERF_TEST_K8S_DOCKER_REGISTRY` | the stand's registry (the suite needs one) |
| `WERF_TEST_I1_PM_BINARY` | the pm binary of the chain |
| `WERF_TEST_I1_PM_SHA256` | expected SHA-256 from the pinned artifact state; the test compares it before passing it to DK |
| `WERF_TEST_I1_TRUSTED_INDEXES` | the pinned instrumented index (`repo@sha256:`), passed as `WERF_SBOM_TRUSTED_INDEXES` |
| `WERF_TEST_I1_BASE` | an instrumented base image (an image built from the chain, with its SBOM) |
| `WERF_TEST_I1_BASE_NO_SBOM` | a base image without such an SBOM (any stock image) |
| `WERF_TEST_I1_BUILDER_NATIVE`, `..._BUILDER_GO` | the instrumented `builder/native` and `builder/golang-alt-1.27` |
| `WERF_TEST_I1_PM_PACKAGE`, `..._PM_PACKAGE_FILE` | a data package of the index and one of its files (for example `tzdata`, `/usr/share/zoneinfo/UTC`) |
| `WERF_TEST_I1_OTHER_INDEX` | an instrumented index that does not hold `PM_PACKAGE`'s source |

Use the agreed increment pins. A pilot run is diagnostic only and does not count as acceptance.
`BASE` must include the instrumented pm executable and its registry/index environment for package-install cases.

## Running

`render.sh` renders every fixture with placeholder values using the Delivery Kit binary (no image is
built, no registry is read). `run.sh` renders, then runs the specs; run it on the build host under its
lock (`state/linux-host.lock`).
