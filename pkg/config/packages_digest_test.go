package config

import (
	"fmt"
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func packagesDigestTestDirectives() []*PackagesDirective {
	envs := []map[string]string{
		nil,
		{"GOPROXY": "direct"},
		{"GOPROXY": "%secret:proxy%"},
		{"A": "1", "B": "%secret:b%", "PACKAGES_VERSION": "%secret:PACKAGES_VERSION%"},
		{"PACKAGES_VERSION": "1.2.3", "REGISTRY": "registry.example.com"},
	}

	var directives []*PackagesDirective
	for pkgType, eco := range Ecosystems() {
		if pkgType == PackagesDirectiveTypeOSPM {
			for _, env := range envs {
				directives = append(directives, &PackagesDirective{Type: pkgType, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: env})
			}
			continue
		}

		for _, lock := range []string{"", eco.DefaultLockFile, "custom.lock"} {
			for _, manager := range []string{"", "/app/bin/tool"} {
				for _, env := range envs {
					directives = append(directives, &PackagesDirective{
						Type:      pkgType,
						FileBased: FileBasedSpec{Workdir: "/app dir", Spec: "spec.file", Lock: lock, Manager: manager},
						Env:       env,
					})
				}
			}
		}
	}

	return directives
}

var _ = Describe("GeneratePackagesDigestInputs", func() {
	It("renders every directive exactly as the commands the stage runs", func() {
		directives := packagesDigestTestDirectives()
		for _, directive := range directives {
			Expect(GeneratePackagesDigestInputs([]*PackagesDirective{directive})).
				To(Equal(GeneratePackagesCommands([]*PackagesDirective{directive})), fmt.Sprintf("%+v", directive))
		}
		Expect(GeneratePackagesDigestInputs(directives)).To(Equal(GeneratePackagesCommands(directives)))
	})

	It("renders the guards with the frozen functions", func() {
		Expect(reflect.ValueOf(digestPackagesGuards.lock).Pointer()).To(Equal(reflect.ValueOf(legacyLockGuard).Pointer()))
		Expect(reflect.ValueOf(digestPackagesGuards.version).Pointer()).To(Equal(reflect.ValueOf(legacyPackagesVersionGuard).Pointer()))
	})

	It("keeps the digest when only the wording of the guards the stage runs changes", func() {
		directives := packagesDigestTestDirectives()
		commandsBefore := GeneratePackagesCommands(directives)
		digestBefore := GeneratePackagesDigestInputs(directives)

		live := execPackagesGuards
		DeferCleanup(func() { execPackagesGuards = live })
		execPackagesGuards = packagesGuards{
			lock: func(files FileBasedSpec) string {
				return strings.Replace(live.lock(files), "commit it", "commit it next to the spec", 1)
			},
			version: func() string {
				return strings.Replace(live.version(), "werf records it", "werf records PACKAGES_VERSION", 1)
			},
		}

		commandsAfter := GeneratePackagesCommands(directives)
		Expect(GeneratePackagesDigestInputs(directives)).To(Equal(digestBefore))
		changed := 0
		for i := range commandsBefore {
			if commandsAfter[i] != commandsBefore[i] {
				changed++
			}
		}
		Expect(changed).To(BeNumerically(">", len(directives)/2))
	})

	It("changes the digest when a step other than a guard changes", func() {
		directive := &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Lock: "go.sum"}}
		changed := *directive
		changed.Env = map[string]string{"GOFLAGS": "-mod=mod"}

		Expect(GeneratePackagesDigestInputs([]*PackagesDirective{&changed})).
			NotTo(Equal(GeneratePackagesDigestInputs([]*PackagesDirective{directive})))
	})
})
