# Embedded composition gate migration

The gate reads `pm.buildinfo/v1` from `.note.package` through the shared pm
reader pinned in `go.mod`. There is no copied parser, compiler sidecar replay,
Git source inventory, or embedded self-hash. An artifact retains its complete
record in the versioned catalog (`dk:catalog/v4`); required metadata is re-read from surviving ELF
bytes, including inherited package files. External catalog hashes detect changed
known files. Missing metadata is an error even when a package owner is known.

Current integration supports C-static, C-dynamic and pure Go on Linux/amd64.
Other profiles fail explicitly. The shared reader validates typed Go module
mappings against final ELF buildinfo Deps. The pure-Go consumer fixture is a real
instrumented ELF with an explicit empty dependency mapping; its SDK originals
were synthetic test inputs, not delivered SDK acceptance. CGO and the full module
matrix remain separate integration work. Main validation and filtering remain
producer-side. The reader
does not re-hash unavailable intermediate objects, archives or sources. Their
composition is the trusted producer's verified claim.

Embedded component identity preserves source kind, locator, version and source checksum.
The catalog keeps complete empty inputs distinct from missing or incomplete data,
and only carries surviving files. Package owners are stored separately from
embedded composition so repeated checks against the package inventory remain stable. Runtime DT_NEEDED/PT_INTERP edges are separate
from intrinsic components. Every library in the checked scope is inventoried;
no dlopen declaration or complete programmatic loading graph is implied.

Dynamic resolution still pins the Linux/amd64 loader and its default directories,
and supports RUNPATH and symlinks. Unknown loader configurations and conflicting
SONAME owners within an executable closure fail.

## Remaining integration

This draft still selects the experimental path through `WERF_DK_NATIVE_POLICY`
(`dk.policy/v2`): tools, profiles, and image roles/output lists. These are temporary
POC controls, not the intended default-on interface. Policies no longer accept
source inventories, SDK distributions or metadata directories. Example profile IDs
are `c-static` and `c-dynamic`, not the old combined language/link-mode strings.

SBOM-enabled os-pm directives request `--sbom-sources-file` at the shared receipt
path. The builder image must provide a pm binary supporting that option; command
generation alone does not establish receipt capture or source verification.
Non-SBOM directives retain their previous commands. The changed command also
changes the packages-stage checksum for SBOM-enabled os-pm builds; there is no
separate SBOM cache-version tag or migration.

The existing pm files inventory adapter also remains a migration dependency: its
`files.json` assumptions must be replaced with pinned original package data and
scoped source candidates. This path must be joined to the ordinary pm/Go/Python/Node pipeline
before enabling verification by default. PE/Mach-O and other pilot formats need
their agreed profiles. None of these gaps is an exemption for toolchain binaries.

`task test:native-poc` verifies the pinned loader and native-inspect fixtures plus
`DK_GO_FIXTURE` (the real pure-Go ELF and expected record), then runs all nativegate
specs without skips. They cover the reader/consumer and runtime layers; illustrative
records are not producer attestations. End-to-end dev producer/package fixtures,
registry publication/read-back, and complete pilot coverage remain separate
acceptance requirements.
