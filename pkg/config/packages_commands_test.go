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

	It("prepends single env var as inline prefix before pm install", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"CUSTOM_VAR": "hello-world"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`CUSTOM_VAR="hello-world" pm install curl`))
	})

	It("prepends DOCKER_CONFIG env var before pm install", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"DOCKER_CONFIG": "/run/secrets/docker-config"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`DOCKER_CONFIG="/run/secrets/docker-config" pm install curl`))
	})

	It("prepends multiple env vars sorted alphabetically before pm install", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"ZZZ": "last", "AAA": "first"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`AAA="first"`))
		Expect(cmds[0]).To(ContainSubstring(`ZZZ="last"`))
		Expect(cmds[0]).To(HaveSuffix("pm install curl"))
	})

	It("prepends proxy env vars before pm install", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{
				"HTTP_PROXY":  "http://proxy.example.com:8080",
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`HTTP_PROXY="http://proxy.example.com:8080"`))
		Expect(cmds[0]).To(ContainSubstring(`HTTPS_PROXY="http://proxy.example.com:8080"`))
		Expect(cmds[0]).To(ContainSubstring("pm install curl"))
	})

	It("prepends DEBIAN_FRONTEND env var before pm install", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"tzdata"}}, Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`DEBIAN_FRONTEND="noninteractive"`))
		Expect(cmds[0]).To(ContainSubstring("pm install tzdata"))
	})

	It("prepends empty string value as quoted empty string", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"SOME_VAR": ""}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring(`SOME_VAR="" pm install curl`))
	})

	It("is backward compatible when env is nil", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(HaveSuffix("pm install curl"))
	})

	It("is backward compatible when env is empty map", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(HaveSuffix("pm install curl"))
	})
})

var _ = Describe("GeneratePackagesCommands non-os-pm ignores env", func() {
	It("ignores env for go-mod package type", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"GOPROXY": "http://proxy:8080"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("go mod download"))
		Expect(cmds[0]).ToNot(ContainSubstring("GOPROXY"))
	})

	It("ignores env for python-pip package type", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://private-pypi"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("pip install"))
		Expect(cmds[0]).ToNot(ContainSubstring("PIP_INDEX_URL"))
	})

	It("ignores env for rust-cargo package type", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("cargo fetch"))
		Expect(cmds[0]).ToNot(ContainSubstring("CARGO_NET_GIT_FETCH_WITH_CLI"))
	})
})
