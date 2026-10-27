# Experimental native SBOM gate

This opt-in proof of concept validates provenance before publishing a Stapel image
SBOM. Set `WERF_DK_NATIVE_POLICY` to a JSON file with schema `dk.policy/v2`.
Without this variable, the existing SBOM path remains selected. This is not a
stable policy API or a production-default feature.

The policy declares tool identities, supported profiles, original SDK/module
distributions and per-image roles (`produce` or `final`). See `types.go`,
`distribution.go` and `modules.go` for the experimental fields. Original project
source hashes come from the built Git commit and effective mappings, rather than
from files created by shell commands. The gate checks original pm inventories,
compiler sidecars, embedded build/link metadata and language-specific metadata.
Final file hashes bind composition after transformations such as strip.

The policy contributes to SBOM cache identity; validation runs again even when an
SBOM artifact already exists. Base/import catalogs preserve intrinsic ownership.
Final composition follows surviving artifacts and selected static members, so
removing a source archive does not remove its code from a surviving executable.

## Runtime and trust boundary

Linux/amd64 ELF and pinned toolchain profiles only. Dynamic resolution accepts a
specific loader hash and its `/lib64`, `/usr/lib64` defaults, plus supported RUNPATH.
Conflicting owners for the same SONAME within one executable closure are rejected;
independent executables have separate closures. This is not a general loader emulator.
`runtimeLoads` is a required user declaration for ELF images, including static ones.

The build environment, tools and original inventories are trusted. Hash checking
is not a signature scheme. Arbitrary generated sources, user assembly, unsupported
compiler features and ambiguous ownership can fail conservatively. Copied foreign
source inside declared project files and opaque unrecognized file formats are not
universally detected. Compiler evidence must survive alongside artifact caches.
Invalidation for changed native headers/libraries in upstream Go caches is not
implemented by this gate.

## Acceptance and remaining delivery work

`task test:native-poc` requires `DK_LOADER_FIXTURE` and
`DK_NATIVE_INSPECT_FIXTURE`. It checks pinned fixture content and requires every
nativegate spec to pass with zero skips. Portable unit runs may skip these specs.
The fixture generators and complete end-to-end environment are not yet delivered
in this repository; the target is not currently self-contained on a fresh checkout.

The source was frozen after staged real-image experiments and independent review.
Full-repository tests and an uninterrupted cold build of all producer tools have
not been completed. Do not interpret a scoped acceptance pass as production readiness.
