package config

import (
	"fmt"
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("generatePackagesDigestInputs", func() {
	It("renders every directive exactly as the commands the stage runs", func() {
		directives := packagesDigestTestDirectives()
		for _, directive := range directives {
			Expect(generatePackagesDigestInputs([]*PackagesDirective{directive})).
				To(Equal(GeneratePackagesCommands([]*PackagesDirective{directive})), fmt.Sprintf("%+v", directive))
		}
		Expect(generatePackagesDigestInputs(directives)).To(Equal(GeneratePackagesCommands(directives)))
	})

	// The expected text is spelled out rather than derived from the package: it is what
	// werf v3.12.0-dk.5 hashed, and any byte of difference rebuilds existing stages.
	DescribeTable("renders the text werf v3.12.0-dk.5 hashed",
		func(directive *PackagesDirective, expected string) {
			Expect(generatePackagesDigestInputs([]*PackagesDirective{directive})).To(Equal([]string{expected}))
		},
		Entry("go-mod with lock and a secret env",
			&PackagesDirective{
				Type:      PackagesDirectiveTypeGoMod,
				FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
				Env:       map[string]string{"GOPROXY": "%secret:proxy%"},
			},
			`cd "/app" && { test -f "go.sum" || { echo 'lock file go.sum not found in /app; the packages stage installs only what the lock pins, commit it' >&2; exit 1; }; } && (GOPROXY="$(</run/secrets/proxy)"; GOPROXY="$GOPROXY" go mod download)`,
		),
		Entry("os-pm with PACKAGES_VERSION from a secret",
			&PackagesDirective{
				Type: PackagesDirectiveTypeOSPM,
				Spec: PackagesSpec{Packages: []string{"curl", "jq"}},
				Env:  map[string]string{"PACKAGES_VERSION": "%secret:PACKAGES_VERSION%"},
			},
			`(PACKAGES_VERSION="$(</run/secrets/PACKAGES_VERSION)"; /.werf/stapel/embedded/bin/mkdir -p /var/lib/pm; : "${PACKAGES_VERSION:?werf records it in the SBOM; set it in packages[].env, e.g. PACKAGES_VERSION: \"%secret:PACKAGES_VERSION%\"}" && printf '%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version; PACKAGES_VERSION="$PACKAGES_VERSION" pm install curl jq)`,
		),
		Entry("javascript-yarn with a custom lock",
			&PackagesDirective{
				Type:      PackagesDirectiveTypeJavaScriptYarn,
				FileBased: FileBasedSpec{Workdir: "/app dir", Spec: "package.json", Lock: "custom.lock"},
			},
			`cd "/app dir" && { test -f "custom.lock" || { echo 'lock file custom.lock not found in /app dir; the packages stage installs only what the lock pins, commit it' >&2; exit 1; }; } && yarn install --frozen-lockfile`,
		),
		Entry("python-pip without a lock guard",
			&PackagesDirective{
				Type:      PackagesDirectiveTypePythonPip,
				FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"},
			},
			`cd "/app" && python3 -P -m pip install --no-cache-dir -r "requirements.txt"`,
		),
	)

	It("wires the stage commands to the live guards and the digest to the frozen ones", func() {
		funcPointer := func(f any) uintptr { return reflect.ValueOf(f).Pointer() }

		Expect(funcPointer(execPackagesGuards().lock)).To(Equal(funcPointer(formatLockGuard)))
		Expect(funcPointer(execPackagesGuards().version)).To(Equal(funcPointer(formatPackagesVersionGuard)))
		Expect(funcPointer(digestPackagesGuards().lock)).To(Equal(funcPointer(legacyLockGuard)))
		Expect(funcPointer(digestPackagesGuards().version)).To(Equal(funcPointer(legacyPackagesVersionGuard)))
	})

	It("keeps the digest when only the wording of the guards the stage runs changes", func() {
		directives := packagesDigestTestDirectives()
		live := execPackagesGuards()
		reworded := packagesGuards{
			lock: func(files FileBasedSpec) string {
				return strings.Replace(live.lock(files), "commit it", "commit it next to the spec", 1)
			},
			version: func() string {
				return strings.Replace(live.version(), "werf records it", "werf records PACKAGES_VERSION", 1)
			},
		}

		commandsBefore := generatePackagesCommands(directives, live)
		commandsAfter := generatePackagesCommands(directives, reworded)
		changed := 0
		for i := range commandsBefore {
			if commandsAfter[i] != commandsBefore[i] {
				changed++
			}
		}
		Expect(changed).To(BeNumerically(">", len(directives)/2))
		Expect(generatePackagesDigestInputs(directives)).To(Equal(commandsBefore))
	})

	It("changes the digest when a step other than a guard changes", func() {
		directive := &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Lock: "go.sum"}}
		changed := *directive
		changed.Env = map[string]string{"GOFLAGS": "-mod=mod"}

		Expect(generatePackagesDigestInputs([]*PackagesDirective{&changed})).
			NotTo(Equal(generatePackagesDigestInputs([]*PackagesDirective{directive})))
	})
})
