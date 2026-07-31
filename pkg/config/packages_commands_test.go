package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("formatSecretVar", func() {
	It("generates a PACKAGES_VERSION template with correct structure", func() {
		tmpl := formatSecretVar("PACKAGES_VERSION")
		Expect(tmpl).To(MatchRegexp(`^PACKAGES_VERSION="\$\{PACKAGES_VERSION:-\$\(.+cat /run/secrets/PACKAGES_VERSION 2>/dev/null \|\| true\)}"$`))
	})

	It("generates a REGISTRY template with correct structure", func() {
		tmpl := formatSecretVar("REGISTRY")
		Expect(tmpl).To(MatchRegexp(`^REGISTRY="\$\{REGISTRY:-\$\(.+cat /run/secrets/REGISTRY 2>/dev/null \|\| true\)}"$`))
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

	type envVarEntry struct {
		directive *PackagesDirective
		checks    []func(cmd string)
	}

	DescribeTable("prepends env vars as inline prefix before pm install",
		func(entry envVarEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			cmd := cmds[0]
			for _, check := range entry.checks {
				check(cmd)
			}
		},

		Entry("single custom env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"CUSTOM_VAR": "hello-world"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`CUSTOM_VAR="hello-world"`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install curl")) },
			},
		}),

		Entry("DOCKER_CONFIG env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"DOCKER_CONFIG": "/run/secrets/docker-config"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DOCKER_CONFIG="/run/secrets/docker-config"`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install curl")) },
			},
		}),

		Entry("multiple env vars sorted alphabetically", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"ZZZ": "last", "AAA": "first"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`AAA="first"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`ZZZ="last"`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install curl")) },
			},
		}),

		Entry("proxy env vars HTTP_PROXY and HTTPS_PROXY", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{
				"HTTP_PROXY":  "http://proxy.example.com:8080",
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTP_PROXY="http://proxy.example.com:8080"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTPS_PROXY="http://proxy.example.com:8080"`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install curl")) },
			},
		}),

		Entry("DEBIAN_FRONTEND env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"tzdata"}}, Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DEBIAN_FRONTEND="noninteractive"`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install tzdata")) },
			},
		}),

		Entry("empty string value", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{"SOME_VAR": ""}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`SOME_VAR=""`)) },
				func(cmd string) { Expect(cmd).To(HaveSuffix("pm install curl")) },
			},
		}),
	)

	DescribeTable("is backward compatible when env is nil or empty",
		func(directive *PackagesDirective) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{directive})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(HaveSuffix("pm install curl"))
		},

		Entry("env is nil", &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}}),
		Entry("env is empty map", &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: map[string]string{}}),
	)
})

var _ = Describe("GeneratePackagesCommands non-os-pm ignores env", func() {
	type nonOsPmEntry struct {
		directive *PackagesDirective
		substring string
		notSubstr string
	}

	DescribeTable("ignores env for non-os-pm package types",
		func(entry nonOsPmEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(ContainSubstring(entry.substring))
			Expect(cmds[0]).ToNot(ContainSubstring(entry.notSubstr))
		},

		Entry("go-mod ignores GOPROXY", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"GOPROXY": "http://proxy:8080"}},
			substring: "go mod download",
			notSubstr: "GOPROXY",
		}),

		Entry("python-pip ignores PIP_INDEX_URL", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://private-pypi"}},
			substring: "pip install",
			notSubstr: "PIP_INDEX_URL",
		}),

		Entry("rust-cargo ignores CARGO_NET_GIT_FETCH_WITH_CLI", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}},
			substring: "cargo fetch",
			notSubstr: "CARGO_NET_GIT_FETCH_WITH_CLI",
		}),
	)
})
