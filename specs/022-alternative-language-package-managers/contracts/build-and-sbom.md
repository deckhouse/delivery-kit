# Build and SBOM Contract

## Package stage

`pkg/build/stage/packages.go` continues to create one network-enabled package stage. `pkg/config.GeneratePackagesCommands` supplies the ordered command sequence. Each alternative ecosystem's wrapped `InstallCmd` emits one complete `if ... then ... else ... fi` block: the `then` branch rejects a pre-installed executable, and the `else` branch uses the command-wrapper factory to create its ephemeral scope, invokes the isolated executable path, and runs associated cleanup after success on separate readable lines under fail-fast shell execution. The generated sequence is included in the existing package-stage checksum so changing an alternative-manager version invalidates the package stage.

Each directive is independent: one directive's bootstrap and cleanup state must not be reused by another directive, even when workdirs or manager families differ.

## SBOM

The existing package ecosystem cataloger mapping remains authoritative:

- Yarn and pnpm use the JavaScript lock cataloger.
- uv and Poetry use the Python package cataloger.
- Source paths remain the configured `workdir/spec` and `workdir/lock`.

The wrapped command's `then` branch rejects an existing manager. Its `else` branch installs the manager in a unique directive-local npm prefix or Python virtual environment, runs dependency installation, and removes that scope with `rm -rf "$scope"` after success. Bootstrap, verification, dependency installation, and cleanup remain ordered on separate readable lines under fail-fast shell execution. Project dependencies and manifest/lock files remain available for the existing SBOM scan; cleanup must not remove them. The temporary path must not be included as nondeterministic checksum input. No new SBOM format or cataloger is introduced.

## Primary package types

`javascript-npm` continues to run `npm ci`; `python-pip` continues to run its current `pip install --no-cache-dir -r ...` command. Neither gets a bootstrap, pre-existing-manager check, or cleanup command.
