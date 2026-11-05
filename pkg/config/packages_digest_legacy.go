package config

import (
	"fmt"

	"al.essio.dev/pkg/shellescape"
)

// The packages stage digest is calculated from text in which these guards are rendered
// with the wording werf v3.12.0-dk.5 shipped, so that changing the wording of the guards
// the stage runs does not rebuild the stage of any existing configuration. NEVER edit
// these functions or let them use anything shared with the live guards; a guard that must
// change what it checks needs a new digest rendering instead.
func legacyLockGuard(files FileBasedSpec) string {
	return fmt.Sprintf(
		`{ test -f %q || { echo %s >&2; exit 1; }; }`,
		files.Lock,
		shellescape.Quote(fmt.Sprintf("lock file %s not found in %s; the packages stage installs only what the lock pins, commit it", files.Lock, files.Workdir)),
	)
}

func legacyPackagesVersionGuard() string {
	return `: "${PACKAGES_VERSION:?werf records it in the SBOM; set it in packages[].env, e.g. PACKAGES_VERSION: \"%secret:PACKAGES_VERSION%\"}"`
}
