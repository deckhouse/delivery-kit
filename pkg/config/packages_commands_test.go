package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/stapel"
)

var _ = Describe("formatSecretVar", func() {
	It("generates a PACKAGES_VERSION template with correct structure", func() {
		tmpl := formatSecretVar("PACKAGES_VERSION")
		Expect(tmpl).To(MatchRegexp(`^PACKAGES_VERSION="\$\{PACKAGES_VERSION:-\$\(\S*head /run/secrets/PACKAGES_VERSION 2>/dev/null \|\| true\)}"$`))
	})

	It("generates a REGISTRY template with correct structure", func() {
		tmpl := formatSecretVar("REGISTRY")
		Expect(tmpl).To(MatchRegexp(`^REGISTRY="\$\{REGISTRY:-\$\(\S*head /run/secrets/REGISTRY 2>/dev/null \|\| true\)}"$`))
	})
})

var _ = Describe("GeneratePackagesCommands os-pm", func() {
	It("produces a single command that creates dir and installs packages", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
		})
		Expect(cmds).To(HaveLen(1))
		cmd := cmds[0]
		Expect(cmd).To(ContainSubstring("mkdir -p /var/lib/pm"))
		Expect(cmd).To(ContainSubstring(`PACKAGES_VERSION="${PACKAGES_VERSION:-$(`))
		Expect(cmd).To(ContainSubstring(`REGISTRY="${REGISTRY:-$(`))
		Expect(cmd).To(ContainSubstring("pm install curl jq"))
	})

	It("includes package names in pm install command", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl==8.12.1", "jq"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("pm install curl==8.12.1 jq"))
	})

	It("reads secrets with the scratch-safe stapel head binary, not the removed cat", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("/.werf/stapel/embedded/bin/head /run/secrets/PACKAGES_VERSION"))
		Expect(cmds[0]).NotTo(ContainSubstring("/.werf/stapel/embedded/bin/cat"))
		Expect(cmds[0]).NotTo(ContainSubstring("$(< /run/secrets/"))
	})

	It("each os-pm directive becomes one command", func() {
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"CUSTOM_VAR": "hello-world"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`CUSTOM_VAR="hello-world"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
				func(cmd string) { Expect(cmd).NotTo(ContainSubstring(`; pm install`)) },
			},
		}),

		Entry("DOCKER_CONFIG env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"DOCKER_CONFIG": "/run/secrets/docker-config"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DOCKER_CONFIG="/run/secrets/docker-config"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
				func(cmd string) { Expect(cmd).NotTo(ContainSubstring(`; pm install`)) },
			},
		}),

		Entry("multiple env vars sorted alphabetically", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"ZZZ": "last", "AAA": "first"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`AAA="first"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`ZZZ="last"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("proxy env vars HTTP_PROXY and HTTPS_PROXY", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{
				"HTTP_PROXY":  "http://proxy.example.com:8080",
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTP_PROXY="http://proxy.example.com:8080"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTPS_PROXY="http://proxy.example.com:8080"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("DEBIAN_FRONTEND env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DEBIAN_FRONTEND="noninteractive"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("empty string value", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"SOME_VAR": ""}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`SOME_VAR=""`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),
	)

	DescribeTable("is backward compatible when env is nil or empty",
		func(directive *PackagesDirective) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{directive})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(ContainSubstring("pm install curl jq"))
		},

		Entry("env is nil", &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}}),
		Entry("env is empty map", &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{}}),
	)
})

var _ = Describe("GeneratePackagesCommands non-os-pm backward compatible", func() {
	type backwardCompatEntry struct {
		directive *PackagesDirective
		substring string
	}

	DescribeTable("produces unchanged command when env is nil or empty",
		func(entry backwardCompatEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			cmd := cmds[0]
			if isAlternativeManager(entry.directive.Type) {
				Expect(cmd).To(ContainSubstring(entry.directive.FileBased.Version))
				Expect(cmd).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
				Expect(cmd).To(ContainSubstring("/.werf/stapel/embedded/bin/rm -rf \"$scope\""))
				if entry.directive.Type == PackagesDirectiveTypePythonUV || entry.directive.Type == PackagesDirectiveTypePythonPoetry {
					Expect(cmd).To(ContainSubstring("sync"))
				} else {
					Expect(cmd).To(ContainSubstring("install --frozen-lockfile"))
				}
				return
			}
			Expect(cmd).To(Equal(entry.substring))
		},

		Entry("GoMod env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}},
			substring: `cd "/app" && go mod download`,
		}),
		Entry("GoMod env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{}},
			substring: `cd "/app" && go mod download`,
		}),
		Entry("PythonUV env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "0.4.20"}},
			substring: `unused`,
		}),
		Entry("PythonUV env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "0.4.20"}, Env: map[string]string{}},
			substring: `unused`,
		}),
		Entry("PythonPip env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}},
			substring: `cd "/app" && pip install --no-cache-dir -r "requirements.txt"`,
		}),
		Entry("PythonPip env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{}},
			substring: `cd "/app" && pip install --no-cache-dir -r "requirements.txt"`,
		}),
		Entry("PythonPoetry env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "2.1.3"}},
			substring: `unused`,
		}),
		Entry("PythonPoetry env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "2.1.3"}, Env: map[string]string{}},
			substring: `unused`,
		}),
		Entry("RustCargo env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}},
			substring: `cd "/app" && cargo fetch`,
		}),
		Entry("RustCargo env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{}},
			substring: `cd "/app" && cargo fetch`,
		}),
		Entry("JavaScriptNpm env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}},
			substring: `cd "/app" && npm ci`,
		}),
		Entry("JavaScriptNpm env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{}},
			substring: `cd "/app" && npm ci`,
		}),
		Entry("JavaScriptYarn env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}},
			substring: `unused`,
		}),
		Entry("JavaScriptYarn env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}, Env: map[string]string{}},
			substring: `unused`,
		}),
		Entry("JavaScriptPnpm env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "9.15.4"}},
			substring: `unused`,
		}),
		Entry("JavaScriptPnpm env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "9.15.4"}, Env: map[string]string{}},
			substring: `unused`,
		}),
		Entry("LuaRock env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeLuaRock, FileBased: FileBasedSpec{Workdir: "/app", Spec: "rockspec"}},
			substring: `cd "/app" && luarocks install --only-deps "rockspec"`,
		}),
		Entry("LuaRock env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeLuaRock, FileBased: FileBasedSpec{Workdir: "/app", Spec: "rockspec"}, Env: map[string]string{}},
			substring: `cd "/app" && luarocks install --only-deps "rockspec"`,
		}),
	)
})

var _ = Describe("GeneratePackagesCommands non-os-pm passes env", func() {
	type nonOsPmEntry struct {
		directive *PackagesDirective
		substring string
		envPrefix string
	}

	DescribeTable("passes env vars as inline prefix for non-os-pm package types",
		func(entry nonOsPmEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(ContainSubstring(entry.substring))
			Expect(cmds[0]).To(ContainSubstring(entry.envPrefix))
		},

		Entry("go-mod passes GOPROXY", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"GOPROXY": "http://proxy:8080"}},
			substring: "go mod download",
			envPrefix: `GOPROXY="http://proxy:8080"`,
		}),

		Entry("python-pip passes PIP_INDEX_URL", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://private-pypi"}},
			substring: "pip install",
			envPrefix: `PIP_INDEX_URL="http://private-pypi"`,
		}),

		Entry("rust-cargo passes CARGO_NET_GIT_FETCH_WITH_CLI", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}},
			substring: "cargo fetch",
			envPrefix: `CARGO_NET_GIT_FETCH_WITH_CLI="true"`,
		}),
	)

	type langEnvVarEntry struct {
		directive  *PackagesDirective
		substring  string
		envVarName string
		envValue   string
	}

	DescribeTable("prepends language-specific env vars as inline prefix",
		func(entry langEnvVarEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(ContainSubstring(entry.substring))
			Expect(cmds[0]).To(ContainSubstring(entry.envVarName + `="` + entry.envValue + `"`))
		},

		Entry("GoMod with GOPROXY=direct", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"GOPROXY": "direct"}},
			substring:  `cd "/app" && go mod download`,
			envVarName: "GOPROXY",
			envValue:   "direct",
		}),

		Entry("PythonUV with UV_EXTRA_INDEX_URL", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "0.4.20"}, Env: map[string]string{"UV_EXTRA_INDEX_URL": "http://pypi:8080"}},
			substring:  `sync --frozen`,
			envVarName: "UV_EXTRA_INDEX_URL",
			envValue:   "http://pypi:8080",
		}),

		Entry("PythonPip with PIP_INDEX_URL", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://pypi:8080"}},
			substring:  `cd "/app" && pip install --no-cache-dir -r "requirements.txt"`,
			envVarName: "PIP_INDEX_URL",
			envValue:   "http://pypi:8080",
		}),

		Entry("PythonPoetry with POETRY_HTTP_BASIC_MYREGISTRY_USERNAME", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "2.1.3"}, Env: map[string]string{"POETRY_HTTP_BASIC_MYREGISTRY_USERNAME": "user"}},
			substring:  `sync --no-root`,
			envVarName: "POETRY_HTTP_BASIC_MYREGISTRY_USERNAME",
			envValue:   "user",
		}),

		Entry("RustCargo with CARGO_NET_RETRY", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_RETRY": "3"}},
			substring:  `cd "/app" && cargo fetch`,
			envVarName: "CARGO_NET_RETRY",
			envValue:   "3",
		}),

		Entry("JavaScriptNpm with npm_config__authtoken", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"npm_config__authtoken": "token"}},
			substring:  `cd "/app" && npm ci`,
			envVarName: "npm_config__authtoken",
			envValue:   "token",
		}),

		Entry("JavaScriptYarn with YARN_ENABLE_IMMUTABLE_INSTALLS", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}, Env: map[string]string{"YARN_ENABLE_IMMUTABLE_INSTALLS": "false"}},
			substring:  `install --frozen-lockfile`,
			envVarName: "YARN_ENABLE_IMMUTABLE_INSTALLS",
			envValue:   "false",
		}),

		Entry("JavaScriptPnpm with PNPM_HOME", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "9.15.4"}, Env: map[string]string{"PNPM_HOME": "/custom/path"}},
			substring:  `install --frozen-lockfile`,
			envVarName: "PNPM_HOME",
			envValue:   "/custom/path",
		}),

		Entry("LuaRock with LUAROCKS_PROXY", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeLuaRock, FileBased: FileBasedSpec{Workdir: "/app", Spec: "rockspec"}, Env: map[string]string{"LUAROCKS_PROXY": "http://proxy:8080"}},
			substring:  `cd "/app" && luarocks install --only-deps "rockspec"`,
			envVarName: "LUAROCKS_PROXY",
			envValue:   "http://proxy:8080",
		}),
	)
})

var _ = Describe("GeneratePackagesCommands non-os-pm multiple env vars", func() {
	type multiEnvVarEntry struct {
		directive *PackagesDirective
		substring string
		checks    []func(cmd string)
	}

	DescribeTable("prepends multiple env vars sorted alphabetically",
		func(entry multiEnvVarEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			cmd := cmds[0]
			Expect(cmd).To(ContainSubstring(entry.substring))
			for _, check := range entry.checks {
				check(cmd)
			}
		},

		Entry("GoMod with A_VAR and Z_VAR are sorted alphabetically", multiEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"Z_VAR": "z", "A_VAR": "a"}},
			substring: `cd "/app" && go mod download`,
			checks: []func(cmd string){
				func(cmd string) {
					Expect(strings.Index(cmd, `A_VAR="a"`)).To(BeNumerically("<", strings.Index(cmd, `Z_VAR="z"`)))
				},
			},
		}),

		Entry("PythonUV with two env vars sorted alphabetically", multiEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "0.4.20"}, Env: map[string]string{"BBB": "two", "AAA": "one"}},
			substring: `sync --frozen`,
			checks: []func(cmd string){
				func(cmd string) {
					Expect(strings.Index(cmd, `AAA="one"`)).To(BeNumerically("<", strings.Index(cmd, `BBB="two"`)))
				},
			},
		}),

		Entry("JavaScriptNpm with three env vars sorted alphabetically", multiEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"Z_LAST": "3", "M_MID": "2", "A_FIRST": "1"}},
			substring: `cd "/app" && npm ci`,
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(HavePrefix(`A_FIRST="1"`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`A_FIRST="1" M_MID="2" Z_LAST="3"`)) },
			},
		}),
	)
})

var _ = Describe("GeneratePackagesCommands non-os-pm proxy env vars", func() {
	type proxyEnvVarEntry struct {
		directive *PackagesDirective
		substring string
	}

	DescribeTable("prepends HTTP_PROXY and HTTPS_PROXY as inline prefix",
		func(entry proxyEnvVarEntry) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{entry.directive})
			Expect(cmds).To(HaveLen(1))
			cmd := cmds[0]
			Expect(cmd).To(ContainSubstring(entry.substring))
			Expect(cmd).To(ContainSubstring(`HTTP_PROXY="http://proxy:8080"`))
			Expect(cmd).To(ContainSubstring(`HTTPS_PROXY="https://proxy:8443"`))
		},

		Entry("GoMod with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cd "/app" && go mod download`,
		}),

		Entry("PythonPip with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cd "/app" && pip install --no-cache-dir -r "requirements.txt"`,
		}),

		Entry("RustCargo with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cd "/app" && cargo fetch`,
		}),

		Entry("JavaScriptNpm with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cd "/app" && npm ci`,
		}),

		Entry("JavaScriptYarn with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `install --frozen-lockfile`,
		}),
	)
})

var _ = Describe("GeneratePackagesCommands alternative managers", func() {
	DescribeTable("matches the independent golden command expectation",
		func(directive *PackagesDirective, goldenFile string) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{directive})
			Expect(cmds).To(HaveLen(1))
			Expect(strings.TrimSpace(normalizeAlternativeManagerScope(cmds[0]))).To(Equal(strings.TrimSpace(readPackagesCommandGolden(goldenFile))))
		},
		Entry("yarn", &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}}, "javascript-yarn.golden"),
		Entry("pnpm", &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "9.15.4"}}, "javascript-pnpm.golden"),
		Entry("uv", &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "0.8.17"}}, "python-uv.golden"),
		Entry("poetry", &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "2.1.3"}}, "python-poetry.golden"),
	)

	It("checks the selected manager before bootstrapping", func() {
		cmd := GeneratePackagesCommands([]*PackagesDirective{{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: "1.22.22"}}})[0]
		Expect(cmd).To(ContainSubstring("if command -v yarn >/dev/null 2>&1; then"))
	})

	DescribeTable("changes to the workdir before alternative-manager bootstrap", func(typeName PackagesDirectiveType, bootstrap string) {
		cmd := GeneratePackagesCommands([]*PackagesDirective{{Type: typeName, FileBased: FileBasedSpec{Workdir: "/app", Spec: "manifest", Version: "1.2.3"}}})[0]
		workdirIndex := strings.Index(cmd, `cd "/app"`)
		bootstrapIndex := strings.Index(cmd, bootstrap)
		Expect(workdirIndex).To(BeNumerically(">=", 0))
		Expect(bootstrapIndex).To(BeNumerically(">", workdirIndex))
	},
		Entry("Yarn", PackagesDirectiveTypeJavaScriptYarn, "npm install --prefix"),
		Entry("pnpm", PackagesDirectiveTypeJavaScriptPnpm, "npm install --prefix"),
		Entry("uv", PackagesDirectiveTypePythonUV, "python3 -m venv"),
		Entry("Poetry", PackagesDirectiveTypePythonPoetry, "python3 -m venv"),
	)

	It("keeps primary manager commands unchanged", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}},
			{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}},
		})
		Expect(cmds).To(ConsistOf(`cd "/app" && npm ci`, `cd "/app" && pip install --no-cache-dir -r "requirements.txt"`))
	})
})

var _ = Describe("GeneratePackagesCommands alternative manager failures", func() {
	type alternativeFailureEntry struct {
		directiveType PackagesDirectiveType
		manager       string
		version       string
	}

	DescribeTable("stops before dependency installation when bootstrap or version verification fails",
		func(entry alternativeFailureEntry, bootstrapMode, managerVersion string, expectedExitCode int) {
			cmd, env, markers := prepareAlternativeManagerCommand(entry, bootstrapMode, managerVersion, 0)
			result := exec.Command("sh", "-e", "-c", cmd)
			result.Env = env
			err := result.Run()

			var exitError *exec.ExitError
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(exitError))
			Expect(err.(*exec.ExitError).ExitCode()).To(Equal(expectedExitCode))
			Expect(markers.dependency).NotTo(BeAnExistingFile())
			Expect(markers.cleanup).NotTo(BeAnExistingFile())
			if bootstrapMode == "fail" {
				Expect(markers.bootstrap).NotTo(BeAnExistingFile())
			} else {
				Expect(markers.bootstrap).To(BeAnExistingFile())
			}
		},
		Entry("Yarn bootstrap failure", alternativeFailureEntry{PackagesDirectiveTypeJavaScriptYarn, "yarn", "1.22.22"}, "fail", "", 17),

		Entry("pnpm bootstrap failure", alternativeFailureEntry{PackagesDirectiveTypeJavaScriptPnpm, "pnpm", "9.15.4"}, "fail", "", 17),
	)

	DescribeTable("returns dependency failure and skips successful-install cleanup",
		func(entry alternativeFailureEntry) {
			cmd, env, markers := prepareAlternativeManagerCommand(entry, "success", entry.version, 23)
			result := exec.Command("sh", "-e", "-c", cmd)
			result.Env = env
			err := result.Run()

			Expect(err).To(HaveOccurred())
			Expect(err.(*exec.ExitError).ExitCode()).To(Equal(23))
			Expect(markers.bootstrap).To(BeAnExistingFile())
			Expect(markers.dependency).To(BeAnExistingFile())
			Expect(markers.cleanup).NotTo(BeAnExistingFile())
			Expect(markers.scope).To(BeAnExistingFile())
		},
		Entry("Yarn", alternativeFailureEntry{PackagesDirectiveTypeJavaScriptYarn, "yarn", "1.22.22"}),
		Entry("pnpm", alternativeFailureEntry{PackagesDirectiveTypeJavaScriptPnpm, "pnpm", "9.15.4"}),
	)
})

func readPackagesCommandGolden(name string) string {
	contents, err := os.ReadFile(filepath.Join("..", "build", "stage", "testdata", "packages_commands", name))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(contents)
}

func normalizeAlternativeManagerScope(command string) string {
	return regexp.MustCompile(`/tmp/werf-packages-[0-9a-f-]+`).ReplaceAllString(command, "/tmp/werf-packages-UUID")
}

const (
	alternativeManagerScriptTemplate = `#!/bin/sh
touch %q
exit %d
`
	alternativeManagerNpmScriptTemplate = `#!/bin/sh
if [ "$BOOTSTRAP_MODE" = "fail" ]; then exit 17; fi
touch %q
prefix=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--prefix" ]; then prefix="$arg"; fi
  previous="$arg"
done
mkdir -p "$prefix/node_modules/.bin"
cp "$MANAGER_TEMPLATE" "$prefix/node_modules/.bin/%s"
chmod 755 "$prefix/node_modules/.bin/%s"
`
	alternativeManagerMkdirScriptTemplate = `#!/bin/sh
exec /bin/mkdir "$@"
`
)

func prepareAlternativeManagerCommand(entry struct {
	directiveType PackagesDirectiveType
	manager       string
	version       string
}, bootstrapMode, managerVersion string, dependencyExitCode int,
) (string, []string, struct{ dependency, cleanup, bootstrap, scope string }) {
	root := GinkgoT().TempDir()
	binDir := filepath.Join(root, "bin")
	Expect(os.Mkdir(binDir, 0o755)).To(Succeed())

	dependencyMarker := filepath.Join(root, "dependency")
	cleanupMarker := filepath.Join(root, "cleanup")
	bootstrapMarker := filepath.Join(root, "bootstrap")
	scopePath := filepath.Join(root, "scope")
	managerTemplate := filepath.Join(root, "manager")
	npmPath := filepath.Join(binDir, "npm")
	mkdirPath := filepath.Join(binDir, "mkdir")
	rmPath := filepath.Join(binDir, "rm")

	managerScript := fmt.Sprintf(alternativeManagerScriptTemplate, dependencyMarker, dependencyExitCode)
	Expect(os.WriteFile(managerTemplate, []byte(managerScript), 0o755)).To(Succeed())

	npmScript := fmt.Sprintf(alternativeManagerNpmScriptTemplate, bootstrapMarker, entry.manager, entry.manager)
	Expect(os.WriteFile(npmPath, []byte(npmScript), 0o755)).To(Succeed())

	mkdirScript := alternativeManagerMkdirScriptTemplate
	Expect(os.WriteFile(mkdirPath, []byte(mkdirScript), 0o755)).To(Succeed())
	Expect(os.WriteFile(rmPath, []byte("#!/bin/sh\nexec /bin/rm \"$@\"\n"), 0o755)).To(Succeed())

	directive := &PackagesDirective{Type: entry.directiveType, FileBased: FileBasedSpec{Workdir: root, Spec: "package.json", Version: entry.version}}
	cmd := GeneratePackagesCommands([]*PackagesDirective{directive})[0]
	cmd = strings.ReplaceAll(cmd, stapel.MkdirBinPath(), mkdirPath)
	cmd = strings.ReplaceAll(cmd, stapel.RmBinPath(), filepath.Join(binDir, "rm"))
	cmd = regexp.MustCompile(`/tmp/werf-packages-[0-9a-f-]+`).ReplaceAllString(cmd, scopePath)
	env := append(os.Environ(),
		"PATH="+binDir+":/usr/bin:/bin",
		"BOOTSTRAP_MODE="+bootstrapMode,
		"MANAGER_TEMPLATE="+managerTemplate,
	)
	return cmd, env, struct{ dependency, cleanup, bootstrap, scope string }{dependencyMarker, cleanupMarker, bootstrapMarker, scopePath}
}

var _ = Describe("GeneratePackagesCommands Python alternative managers", func() {
	It("keeps python-pip free of alternative-manager lifecycle commands", func() {
		cmd := GeneratePackagesCommands([]*PackagesDirective{{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}}})[0]
		Expect(cmd).To(Equal(`cd "/app" && pip install --no-cache-dir -r "requirements.txt"`))
		Expect(cmd).NotTo(ContainSubstring("mktemp"))
		Expect(cmd).NotTo(ContainSubstring("venv"))
		Expect(cmd).NotTo(ContainSubstring("rm -rf"))
	})

	It("preserves Python dependency failures before cleanup", func() {
		for _, entry := range []struct {
			typeName PackagesDirectiveType
			manager  string
			install  string
		}{
			{PackagesDirectiveTypePythonUV, "uv", "sync --frozen"},
			{PackagesDirectiveTypePythonPoetry, "poetry", "sync --no-root"},
		} {
			directive := &PackagesDirective{Type: entry.typeName, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml", Version: "1.2.3"}}
			cmd := GeneratePackagesCommands([]*PackagesDirective{directive})[0]
			Expect(cmd).To(ContainSubstring(entry.manager + "==1.2.3"))
			Expect(cmd).To(ContainSubstring(entry.install))
		}
	})

	It("rejects every pre-existing alternative manager before bootstrap", func() {
		entries := []struct {
			typeName PackagesDirectiveType
			manager  string
		}{
			{PackagesDirectiveTypeJavaScriptYarn, "yarn"},
			{PackagesDirectiveTypeJavaScriptPnpm, "pnpm"},
			{PackagesDirectiveTypePythonUV, "uv"},
			{PackagesDirectiveTypePythonPoetry, "poetry"},
		}
		for _, entry := range entries {
			cmd := GeneratePackagesCommands([]*PackagesDirective{{Type: entry.typeName, FileBased: FileBasedSpec{Workdir: "/app", Spec: "manifest", Version: "1.2.3"}}})[0]
			check := "command -v " + entry.manager + " >/dev/null 2>&1"
			Expect(cmd).To(ContainSubstring(check))
			Expect(strings.Index(cmd, check)).To(BeNumerically("<", strings.Index(cmd, `scope="/tmp/werf-packages-`)))
		}
	})

	It("keeps multiple Python directives independent", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/uv", Spec: "pyproject.toml", Version: "0.8.17"}},
			{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/poetry", Spec: "pyproject.toml", Version: "2.1.3"}},
		})
		Expect(cmds).To(HaveLen(2))
		Expect(cmds[0]).To(ContainSubstring(`cd "/uv"`))
		Expect(cmds[0]).To(ContainSubstring("uv==0.8.17"))
		Expect(cmds[0]).NotTo(ContainSubstring("poetry==2.1.3"))
		Expect(cmds[1]).To(ContainSubstring(`cd "/poetry"`))
		Expect(cmds[1]).To(ContainSubstring("poetry==2.1.3"))
		Expect(cmds[1]).NotTo(ContainSubstring("uv==0.8.17"))
		Expect(cmds[0]).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
		Expect(cmds[1]).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
	})
})

var _ = Describe("GeneratePackagesCommands no os-pm", func() {
	It("produces no commands when packages list is nil", func() {
		cmds := GeneratePackagesCommands(nil)
		Expect(cmds).To(BeEmpty())
	})

	It("produces no commands when packages list is empty", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{})
		Expect(cmds).To(BeEmpty())
	})
})
