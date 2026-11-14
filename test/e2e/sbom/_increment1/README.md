# Increment 1 stand: negative scenarios and one positive build

`increment1_test.go` (label `increment1`) builds the fixtures of `../_fixtures/increment1` with a
Delivery Kit binary against an instrumented stand, and checks that each negative scenario is refused
with the file (or package) named, and the positive one builds. Nothing here builds an image by itself:
the specs skip, naming the missing `WERF_TEST_I1_*` variables, until a stand is configured.

| fixture | scenario | expected refusal (a regular expression, as `pkg/sbom/nativegate` words it) |
|---|---|---|
| `pkg-file-replaced` | a file of a pm package changed by a shell stage after installation | `<file>: hash-mismatch: pm original changed` |
| `elf-in-git` | an ELF binary from a git mapping (stock Go build, no `.note.package`) | `/app/tool: no-data: missing (sbom metadata\|build record)` |
| `git-file-edited` | a file of a commit changed by a shell stage | `/app/config.txt: hash-mismatch: git original changed` |
| `package-outside-index` | a pm package whose index is not in `WERF_SBOM_TRUSTED_INDEXES` | `<package>: no-data: package outside instrumented index` |
| `base-without-sbom` | a base image that has no instrumented SBOM | `unable to get base image sbom with ref <base>: the image "<base>" must have an SBOM artifact attached` |
| `foreign-arch` | an instrumented linux/arm64 binary (`WERF_TEST_I1_ARM64_BINARY`) in an amd64 build | `/app/tool: unsupported platform linux/arm64: expected linux/amd64` |
| `base-empty-without-sbom` | an empty registry image without SBOM as base | `unable to get base image sbom with ref <base>: …must have an SBOM artifact attached` |
| `from-scratch` | the `from: scratch` directive, a git file only | builds; the SBOM holds `/app/config.txt` and `dk:verification=instrumented-v1` |
| `positive` | a C program on `builder/native` and a Go program on `builder/golang-alt-1.27` | builds; `/app/hello` is a file component with `dk:origin=build`; the SBOM carries `dk:verification=instrumented-v1` |

Each negative is matched by the gate's own wording, naming the file or package, so a build that fails for
another reason (registry, missing image, flags) does not satisfy it. The positive spec runs first and the
container is Ordered: if it fails, the negatives are skipped.

The reasons are the wording of `pkg/sbom/nativegate`. A change of wording changes the table in the test.

## Variables

Set by the stand (take the values from the state file of the track that publishes the chain):

| variable | meaning |
|---|---|
| `WERF_TEST_BINARY_PATH` | the Delivery Kit binary (`dk-build.sh <sha>` writes it to `.../dk-1/releases/<sha>/werf`) |
| `WERF_TEST_K8S_DOCKER_REGISTRY` | the stand's registry (the suite needs one) |
| `WERF_TEST_I1_PM_BINARY` | the pm binary of the chain; its SHA-256 is computed and passed as `WERF_SBOM_PM_SHA256` |
| `WERF_TEST_I1_TRUSTED_INDEXES` | the pinned instrumented index (`repo@sha256:`), passed as `WERF_SBOM_TRUSTED_INDEXES` |
| `WERF_TEST_I1_BASE` | an instrumented base image (an image built from the chain, with its SBOM) |
| `WERF_TEST_I1_BASE_NO_SBOM_EMPTY` | an EMPTY registry image without an instrumented SBOM, by digest (e.g. `registry.werf.io/werf/scratch@sha256:…`): refused as a base, unlike the `from: scratch` directive |
| `WERF_TEST_I1_BASE_NO_SBOM` | a non-empty stock base image without such an SBOM, by digest (not scratch: an empty base has nothing to verify) |
| `WERF_TEST_I1_BUILDER_NATIVE`, `..._BUILDER_GO` | the instrumented `builder/native` and `builder/golang-alt-1.27` |
| `WERF_TEST_I1_PM_PACKAGE`, `..._PM_PACKAGE_FILE` | a data package of the index and one of its files (for example `tzdata`, `/usr/share/zoneinfo/UTC`) |
| `WERF_TEST_I1_ARM64_BINARY` | an instrumented linux/arm64 ELF (record platform linux/arm64), e.g. a binary of an arm64 package |
| `WERF_TEST_I1_OTHER_INDEX` | an instrumented index that does not hold `PM_PACKAGE`'s source |

Until the chain's builders and index are published, point the variables at the pilot's: the builders
and index of the pilot pipeline (`index:dev-packages`), a pilot base for `BASE`. The pilot builders
and index are the ones the spec's pilot run used; their digests are in the BI-1 state file once published.

## Running

`render.sh` renders every fixture with placeholder values using the Delivery Kit binary (no image is
built, no registry is read). `run.sh` renders, then runs the specs; run it on the build host under its
lock (`state/linux-host.lock`).

## First run on a candidate Delivery Kit (ef2d4c702), partial stand
The stand held no instrumented base, builders or index (BI-1's core was still building), so only the cases that do not
need them were run by hand with the same fixtures (logs in `artifacts/pm-1/e2e-ef2d4c7/`):
`elf-in-git` on `from: scratch` is refused naming `/app/tool` (`no-data: missing sbom metadata`); `base-without-sbom`
on a non-empty stock base is refused naming the base; on the empty `scratch` base it passes (hence the note above);
`git-file-edited` is refused for a file DK itself leaves, `/.werf/tmp/ssh-auth-sock` (`no trusted original`), before
the changed git file is reached.

## Known dependency: git-file-edited
Against candidate ef2d4c702 the `git-file-edited` spec fails for a reason other than the one it checks: the image of
any build with a shell stage holds werf's `/.werf/tmp/ssh-auth-sock`, which the gate refuses ("no trusted original")
before the changed git file is reached. A red `git-file-edited` with that file in the output is that defect, not a
failure to detect the edit. The spec is left active so the defect keeps showing; it turns green only when it is fixed.
