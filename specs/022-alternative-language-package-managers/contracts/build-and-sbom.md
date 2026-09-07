# Build and SBOM Contract

## Package stage

`pkg/build/stage/packages.go` continues to create one network-enabled package stage. `pkg/config.GeneratePackagesCommands` supplies the ordered command sequence. Each alternative ecosystem's wrapped `InstallCmd` uses the command-wrapper factory to create its ephemeral scope, invokes the returned executable path for the existing dependency command, and runs the associated cleanup command after success. The generated sequence is included in the existing package-stage checksum so changing an alternative-manager version invalidates the package stage.

Each directive is independent: one directive's bootstrap and cleanup state must not be reused by another directive, even when workdirs or manager families differ.

## SBOM

The existing package ecosystem cataloger mapping remains authoritative:

- Yarn and pnpm use the JavaScript lock cataloger.
- uv and Poetry use the Python package cataloger.
- Source paths remain the configured `workdir/spec` and `workdir/lock`.

The alternative manager is installed in a unique directive-local npm prefix or Python virtual environment and that scope is removed after dependency installation. Project dependencies and manifest/lock files remain available for the existing SBOM scan; cleanup must not remove them. The temporary path must not be included as nondeterministic checksum input. No new SBOM format or cataloger is introduced.

## Primary package types

`javascript-npm` continues to run `npm ci`; `python-pip` continues to run its current `pip install --no-cache-dir -r ...` command. Neither gets a bootstrap, pre-existing-manager check, or cleanup command.
