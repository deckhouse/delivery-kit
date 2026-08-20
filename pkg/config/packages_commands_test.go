package config

import (
	"strings"

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

	It("uses stapel cat binary path for secret resolution", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("/.werf/stapel/embedded/bin/cat"))
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
			Expect(cmds[0]).To(Equal(entry.substring))
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}},
			substring: `cd "/app" && uv sync --frozen`,
		}),
		Entry("PythonUV env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{}},
			substring: `cd "/app" && uv sync --frozen`,
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}},
			substring: `cd "/app" && poetry sync --no-root`,
		}),
		Entry("PythonPoetry env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{}},
			substring: `cd "/app" && poetry sync --no-root`,
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}},
			substring: `cd "/app" && yarn install --frozen-lockfile`,
		}),
		Entry("JavaScriptYarn env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{}},
			substring: `cd "/app" && yarn install --frozen-lockfile`,
		}),
		Entry("JavaScriptPnpm env is nil", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}},
			substring: `cd "/app" && pnpm install --frozen-lockfile`,
		}),
		Entry("JavaScriptPnpm env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{}},
			substring: `cd "/app" && pnpm install --frozen-lockfile`,
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
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"UV_EXTRA_INDEX_URL": "http://pypi:8080"}},
			substring:  `cd "/app" && uv sync --frozen`,
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
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"POETRY_HTTP_BASIC_MYREGISTRY_USERNAME": "user"}},
			substring:  `cd "/app" && poetry sync --no-root`,
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
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"YARN_ENABLE_IMMUTABLE_INSTALLS": "false"}},
			substring:  `cd "/app" && yarn install --frozen-lockfile`,
			envVarName: "YARN_ENABLE_IMMUTABLE_INSTALLS",
			envValue:   "false",
		}),

		Entry("JavaScriptPnpm with PNPM_HOME", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"PNPM_HOME": "/custom/path"}},
			substring:  `cd "/app" && pnpm install --frozen-lockfile`,
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"BBB": "two", "AAA": "one"}},
			substring: `cd "/app" && uv sync --frozen`,
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(HavePrefix(`AAA="one" BBB="two"`)) },
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
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cd "/app" && yarn install --frozen-lockfile`,
		}),
	)
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
