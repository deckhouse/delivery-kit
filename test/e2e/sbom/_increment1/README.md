# Increment 1 stand: strict verification and cache reuse

`increment1_test.go` (label `increment1`) builds the fixtures of `../_fixtures/increment1` with a
Delivery Kit binary against an instrumented stand, and checks that each negative scenario is refused
with the file (or package) and reason in the same diagnostic, and the positive scenarios build:
the specs skip, naming the missing `WERF_TEST_I1_*` variables, until a stand is configured.

| fixture | scenario | expected refusal (names, reason) |
|---|---|---|
| `pkg-file-replaced` | a file of a pm package changed by a shell stage after installation | `@PM_PACKAGE_FILE@`, `hash-mismatch` |
| `elf-in-git` | an ELF binary from a git mapping (stock Linux `/bin/true`, no instrumented composition) | `/app/tool: no-data: missing sbom metadata` |
| `git-file-edited` | a file of a commit changed by a shell stage | `/app/config.txt`, `hash-mismatch` |
| `package-outside-index` | a pm package whose index is not in `WERF_SBOM_TRUSTED_INDEXES` | `@PM_PACKAGE@`, `outside instrumented index` |
| `base-without-sbom` | a non-empty registry base without SBOM | base reference, `must have an SBOM artifact attached` |
| `base-empty-without-sbom` | an empty registry base without SBOM, including a registry image named scratch | base reference, `must have an SBOM artifact attached` |
| `from-scratch` | literal `from: scratch` without a registry base | builds; `/app/config.txt` appears in the verified SBOM |
| `elf-in-git` with an ARM64 fixture | an instrumented ARM64 ELF in an AMD64 image | `/app/tool: unsupported platform linux/arm64: expected linux/amd64` |
| `positive` | a C program on `builder/native` and a Go program on `builder/golang-alt-1.27` | builds; `/app/hello` is a file component with `dk:origin=build`; the SBOM carries `dk:verification=instrumented-v1` |
| `cache` | two scratch images; repeat unchanged, then change only app setup | no repeated shell execution or stage verification; cached app install and the independent stable image are reused; both app marker files remain in the SBOM |

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
| `WERF_TEST_I1_BASE_NO_SBOM` | a non-empty stock registry image without SBOM |
| `WERF_TEST_I1_BASE_NO_SBOM_EMPTY` | an empty stock registry image without SBOM, pinned by digest |
| `WERF_TEST_I1_BUILDER_NATIVE`, `..._BUILDER_GO` | the instrumented `builder/native` and `builder/golang-alt-1.27` |
| `WERF_TEST_I1_PM_PACKAGE`, `..._PM_PACKAGE_FILE` | a data package of the index and one of its files (for example `tzdata`, `/usr/share/zoneinfo/UTC`) |
| `WERF_TEST_I1_OTHER_INDEX` | an instrumented index containing the sources of `BASE`, but excluding `PM_PACKAGE`'s source; otherwise the refusal may name a base package first |

Use the agreed increment pins. A pilot run is diagnostic only and does not count as acceptance.
`BASE` must include the instrumented pm executable and its registry/index environment for package-install cases.

## Running

`render.sh` renders every fixture with placeholder values using the Delivery Kit binary (no image is
built, no registry is read). `run.sh` renders, then runs the specs; run it on the build host under its
lock (`state/linux-host.lock`).

The cache and literal-scratch cases need only `WERF_TEST_BINARY_PATH`,
`WERF_TEST_K8S_DOCKER_REGISTRY`, `WERF_TEST_I1_PM_BINARY` and `WERF_TEST_I1_PM_SHA256`.
They install no packages, so no trusted index or instrumented builder is required:

```sh
task --yes test:e2e paths=./test/e2e/sbom labelFilter=increment1 parallel=1 -- --focus='reuses unchanged images|builds from literal scratch'
```

The full `run.sh` still requires every stand input. Package-file and C/Go positive cases
also require `TRUSTED_INDEXES` when selected directly.

## The arm64 binary of `foreign-arch`

`arm64-binary.sh` cross-compiles a Go hello for linux/arm64 with plain `docker run` and checks the embedded platform record. It needs an instrumented builder and its helper context; the script does not yet supply `SBOM_BUILD_CONTEXT`. End-to-end execution remains unverified. The synthetic foreign-platform ELF test runs independently of this tool.
