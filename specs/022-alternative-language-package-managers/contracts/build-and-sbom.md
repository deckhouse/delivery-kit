# Build and SBOM Contract

## Package stage

`pkg/build/stage/packages.go` continues to create one network-enabled package stage. `pkg/config.GeneratePackagesCommands` supplies the ordered command sequence. Each alternative ecosystem's wrapped `InstallCmd` emits one readable `if ... fi` block: the existing-manager branch invokes the existing executable without cleanup, while the absent-manager branch uses the command-wrapper factory to create its ephemeral scope, invokes the isolated executable path, and runs associated cleanup after success. The generated sequence is included in the existing package-stage checksum so changing an alternative-manager version invalidates the package stage.

Each directive is independent: one directive's bootstrap and cleanup state must not be reused by another directive, even when workdirs or manager families differ.

## SBOM

The existing package ecosystem cataloger mapping remains authoritative:

- Yarn and pnpm use the JavaScript lock cataloger.
- uv and Poetry use the Python package cataloger.
- Source paths remain the configured `workdir/spec` and `workdir/lock`.

The wrapped command first checks for an existing manager. If found, it uses that executable and performs no manager cleanup. If absent, one readable `if ... fi` branch installs the manager in a unique directive-local npm prefix or Python virtual environment, runs dependency installation, and removes that scope after success. Project dependencies and manifest/lock files remain available for the existing SBOM scan; cleanup must not remove them. The temporary path must not be included as nondeterministic checksum input. No new SBOM format or cataloger is introduced.

## Primary package types

`javascript-npm` continues to run `npm ci`; `python-pip` continues to run its current `pip install --no-cache-dir -r ...` command. Neither gets a bootstrap, pre-existing-manager check, or cleanup command.
