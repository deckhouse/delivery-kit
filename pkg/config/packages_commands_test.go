package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("envVarTmpl", func() {
	It("generates a PACKAGES_VERSION template with correct structure", func() {
		tmpl := envVarTmpl("PACKAGES_VERSION")
		Expect(tmpl).To(MatchRegexp(`^PACKAGES_VERSION="\$\{PACKAGES_VERSION:-\$\(.+cat /run/secrets/PACKAGES_VERSION 2>/dev/null \|\| true\)\}"$`))
	})

	It("generates a REGISTRY template with correct structure", func() {
		tmpl := envVarTmpl("REGISTRY")
		Expect(tmpl).To(MatchRegexp(`^REGISTRY="\$\{REGISTRY:-\$\(.+cat /run/secrets/REGISTRY 2>/dev/null \|\| true\)\}"$`))
	})
})

var _ = Describe("GeneratePackagesCommands os-pm", func() {
	It("produces a single command that creates dir and installs packages", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
		})
		Expect(cmds).To(HaveLen(1))
		cmd := cmds[0]
		Expect(cmd).To(ContainSubstring("mkdir -p /var/lib/pm"))
		Expect(cmd).To(ContainSubstring(`PACKAGES_VERSION="${PACKAGES_VERSION:-$(`))
		Expect(cmd).To(ContainSubstring(`REGISTRY="${REGISTRY:-$(`))
		Expect(cmd).To(HaveSuffix("pm install curl"))
	})

	It("uses stapel cat binary path for secret resolution", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("/.werf/stapel/embedded/bin/cat"))
	})

	It("does not snapshot - each os-pm directive becomes one command", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"jq"}}},
		})
		Expect(cmds).To(HaveLen(2))
		Expect(cmds[0]).To(ContainSubstring("pm install curl"))
		Expect(cmds[1]).To(ContainSubstring("pm install jq"))
	})
})
