package config

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/os_pm/metadata"
	"github.com/werf/werf/v2/pkg/stapel"
)

var _ = Describe("formatEnvVars shell safety", func() {
	readEnvVar := func(ctx SpecContext, name, value string) (string, string, error) {
		assignments, prefix := formatEnvVars(map[string]string{name: value}, nil)
		script := strings.Join(append(assignments, fmt.Sprintf(`%s sh -c 'printf %%s "$%s"'`, prefix, name)), "; ")
		cmd := exec.CommandContext(ctx, "bash", "-ec", script)
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		stdout, err := cmd.Output()
		return string(stdout), stderr.String(), err
	}

	DescribeTable("passes the value to the package manager without letting bash interpret it",
		func(ctx SpecContext, value string) {
			stdout, stderr, err := readEnvVar(ctx, "SOME_VAR", value)
			Expect(err).NotTo(HaveOccurred(), stderr)
			Expect(stdout).To(Equal(value))
		},
		Entry("command substitution", "$(echo pwned)"),
		Entry("backquoted command", "`echo pwned`"),
		Entry("variable expansion", "${HOME}"),
		Entry("glob", "/etc/*"),
		Entry("single quote", "pass'word"),
		Entry("whitespace and semicolon", "a; echo pwned"),
		Entry("empty value", ""),
		Entry("ordinary value", "http://proxy.example.com:8080"),
		Entry("newline and tab", "first\n\tsecond"),
	)
})

var _ = Describe("formatWorkdirCommand", func() {
	It("places the env prefix in front of the package manager, not in front of cd", func() {
		Expect(formatWorkdirCommand("/app", "go mod download", map[string]string{"GOPROXY": "direct"})).
			To(Equal(`cd "/app" && GOPROXY=direct go mod download`))
	})

	It("keeps cd in the parent shell and isolates only a secret-backed value", func() {
		Expect(formatWorkdirCommand("/app", "go mod download", map[string]string{"GOPROXY": "%secret:proxy%"})).
			To(Equal(`cd "/app" && (GOPROXY="$(</run/secrets/proxy)"; GOPROXY="$GOPROXY" go mod download)`))
	})

	It("exposes the env var to the package manager process", func(ctx SpecContext) {
		dir := GinkgoT().TempDir()
		command := formatWorkdirCommand(dir, "printenv SOME_VAR", map[string]string{"SOME_VAR": "some-value"})

		cmd := exec.CommandContext(ctx, "bash", "-ec", command)
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		stdout, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		Expect(string(stdout)).To(Equal("some-value\n"))
	})

	Describe("two directives in one stage script", func() {
		runStage := func(ctx SpecContext, firstEnv, secrets map[string]string) (string, error) {
			dir := GinkgoT().TempDir()
			secretsDir := filepath.Join(dir, "secrets")
			Expect(os.MkdirAll(secretsDir, 0o700)).To(Succeed())
			for id, value := range secrets {
				Expect(os.WriteFile(filepath.Join(secretsDir, id), []byte(value), 0o600)).To(Succeed())
			}

			appDir := filepath.Join(dir, "app")
			Expect(os.MkdirAll(filepath.Join(appDir, "tools"), 0o700)).To(Succeed())

			// The second workdir is relative: it resolves against the `cd` of the first directive,
			// which the shared stage shell keeps between directives.
			script := strings.Join([]string{
				formatWorkdirCommand(appDir, "printenv GOPROXY", firstEnv),
				formatWorkdirCommand("tools", "printenv GOPROXY", nil),
			}, "\n")
			script = strings.ReplaceAll(script, packageSecretsDir, secretsDir+"/")

			cmd := exec.CommandContext(ctx, "bash", "-ec", script)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GOPROXY=base-proxy"}
			stderr := &bytes.Buffer{}
			cmd.Stderr = stderr
			stdout, err := cmd.Output()
			if err != nil {
				return string(stdout), fmt.Errorf("run packages stage script: %w: %s", err, stderr)
			}

			return string(stdout), nil
		}

		DescribeTable("keeps an override of a variable the base image exports local to its own directive",
			func(ctx SpecContext, firstEnv, secrets map[string]string) {
				stdout, err := runStage(ctx, firstEnv, secrets)
				Expect(err).NotTo(HaveOccurred())
				Expect(stdout).To(Equal("private-proxy\nbase-proxy\n"))
			},

			Entry("literal value", map[string]string{"GOPROXY": "private-proxy"}, nil),
			Entry("secret-backed value", map[string]string{"GOPROXY": "%secret:proxy%"}, map[string]string{"proxy": "private-proxy"}),
		)

		It("fails the stage before the next directive when the referenced secret cannot be read", func(ctx SpecContext) {
			stdout, err := runStage(ctx, map[string]string{"GOPROXY": "%secret:proxy%"}, nil)
			Expect(err).To(MatchError(ContainSubstring("proxy: No such file or directory")))
			Expect(stdout).To(BeEmpty())
		})
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
		Expect(cmd).To(ContainSubstring("pm install curl jq"))
	})

	It("includes package names in pm install command", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl==8.12.1", "jq"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).To(ContainSubstring("pm install curl==8.12.1 jq"))
	})

	It("reads no secret the config does not reference", func() {
		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
		})
		Expect(cmds).To(HaveLen(1))
		Expect(cmds[0]).NotTo(ContainSubstring(packageSecretsDir))
	})

	DescribeTable("produces exactly this command, byte for byte",
		func(env map[string]string, expected string) {
			cmds := GeneratePackagesCommands([]*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: env},
			})
			Expect(cmds).To(HaveLen(1))
			Expect(cmds[0]).To(Equal(fmt.Sprintf(expected, stapel.MkdirBinPath(), packagesVersionMissingMessage)))
		},

		Entry("without env", nil,
			`%s -p /var/lib/pm; : "${PACKAGES_VERSION:?%s}" && printf '%%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version; pm install curl jq`),
		Entry("with a secret path, which is a literal and stays inline", map[string]string{"PACKAGES_VERSION": "1.0.0", "DOCKER_CONFIG": "%secret_path:dockercfg%"},
			`(PACKAGES_VERSION=1.0.0; %s -p /var/lib/pm; : "${PACKAGES_VERSION:?%s}" && printf '%%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version; DOCKER_CONFIG=/run/secrets/dockercfg PACKAGES_VERSION="$PACKAGES_VERSION" pm install curl jq)`),
		Entry("with a literal and a secret-backed variable", map[string]string{"PACKAGES_VERSION": "1.0.0", "REGISTRY": "%secret:REGISTRY%"},
			`(PACKAGES_VERSION=1.0.0; REGISTRY="$(</run/secrets/REGISTRY)"; %s -p /var/lib/pm; : "${PACKAGES_VERSION:?%s}" && printf '%%s\n' "$PACKAGES_VERSION" > /var/lib/pm/container-factory-version; PACKAGES_VERSION="$PACKAGES_VERSION" REGISTRY="$REGISTRY" pm install curl jq)`),
	)

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
				func(cmd string) { Expect(cmd).To(ContainSubstring(`CUSTOM_VAR=hello-world`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
				func(cmd string) { Expect(cmd).NotTo(ContainSubstring(`; pm install`)) },
			},
		}),

		Entry("DOCKER_CONFIG env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"DOCKER_CONFIG": "/run/secrets/docker-config"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DOCKER_CONFIG=/run/secrets/docker-config`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
				func(cmd string) { Expect(cmd).NotTo(ContainSubstring(`; pm install`)) },
			},
		}),

		Entry("multiple env vars sorted alphabetically", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"ZZZ": "last", "AAA": "first"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`AAA=first`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`ZZZ=last`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("proxy env vars HTTP_PROXY and HTTPS_PROXY", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{
				"HTTP_PROXY":  "http://proxy.example.com:8080",
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTP_PROXY=http://proxy.example.com:8080`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`HTTPS_PROXY=http://proxy.example.com:8080`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("DEBIAN_FRONTEND env var", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"DEBIAN_FRONTEND": "noninteractive"}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`DEBIAN_FRONTEND=noninteractive`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring("pm install curl jq")) },
			},
		}),

		Entry("empty string value", envVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}, Env: map[string]string{"SOME_VAR": ""}},
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`SOME_VAR=''`)) },
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

var _ = Describe("GeneratePackagesCommands os-pm PACKAGES_VERSION", func() {
	type runResult struct {
		versionFile     string
		installVersion  string
		installRegistry string
	}

	run := func(ctx SpecContext, env map[string]string, baseImageEnv string, secrets map[string]string) (runResult, error) {
		dir := GinkgoT().TempDir()
		secretsDir := filepath.Join(dir, "secrets")
		Expect(os.MkdirAll(secretsDir, 0o700)).To(Succeed())
		for id, value := range secrets {
			Expect(os.WriteFile(filepath.Join(secretsDir, id), []byte(value+"\n"), 0o600)).To(Succeed())
		}

		installEnvFile := filepath.Join(dir, "install-env")
		pmStub := filepath.Join(dir, "pm")
		Expect(os.WriteFile(pmStub, []byte("#!/bin/bash\nprintf '%s\\n%s' \"$PACKAGES_VERSION\" \"$REGISTRY\" > "+installEnvFile+"\n"), 0o700)).To(Succeed())

		cmds := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}, Env: env},
		})
		Expect(cmds).To(HaveLen(1))

		script := cmds[0]
		script = strings.ReplaceAll(script, stapel.MkdirBinPath(), "mkdir")
		script = strings.ReplaceAll(script, packageSecretsDir, secretsDir+"/")
		script = strings.ReplaceAll(script, metadata.ContainerFactoryVersionPath, filepath.Join(dir, "container-factory-version"))
		script = strings.ReplaceAll(script, path.Dir(metadata.ContainerFactoryVersionPath), dir)

		cmd := exec.CommandContext(ctx, "bash", "-ec", script)
		cmd.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH")}
		if baseImageEnv != "" {
			cmd.Env = append(cmd.Env, "PACKAGES_VERSION="+baseImageEnv)
		}
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			return runResult{}, fmt.Errorf("run packages stage script: %w: %s", err, stderr)
		}

		versionFile, err := os.ReadFile(filepath.Join(dir, "container-factory-version"))
		Expect(err).NotTo(HaveOccurred())
		installEnv, err := os.ReadFile(installEnvFile)
		Expect(err).NotTo(HaveOccurred())

		installed := strings.SplitN(string(installEnv), "\n", 2)
		return runResult{
			versionFile:     strings.TrimSuffix(string(versionFile), "\n"),
			installVersion:  installed[0],
			installRegistry: installed[1],
		}, nil
	}

	DescribeTable("records the same version it installs with",
		func(ctx SpecContext, env map[string]string, baseImageEnv string, secrets map[string]string, expected string) {
			result, err := run(ctx, env, baseImageEnv, secrets)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.versionFile).To(Equal(expected))
			Expect(result.installVersion).To(Equal(expected))
		},

		Entry("base image env only", nil, "1.0.0", nil, "1.0.0"),
		Entry("packages env only", map[string]string{"PACKAGES_VERSION": "2.0.0"}, "", nil, "2.0.0"),
		Entry("packages env wins over base image env", map[string]string{"PACKAGES_VERSION": "2.0.0"}, "1.0.0", nil, "2.0.0"),
		Entry("packages env reads a secret", map[string]string{"PACKAGES_VERSION": "%secret:PACKAGES_VERSION%"}, "", map[string]string{"PACKAGES_VERSION": "3.0.0"}, "3.0.0"),
	)

	It("passes a referenced secret to the package manager for any variable", func(ctx SpecContext) {
		result, err := run(ctx,
			map[string]string{"PACKAGES_VERSION": "1.0.0", "REGISTRY": "%secret:REGISTRY%"},
			"", map[string]string{"REGISTRY": "registry.example.com/catalog"},
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.installRegistry).To(Equal("registry.example.com/catalog"))
	})

	DescribeTable("fails the stage instead of installing with a version it cannot record",
		func(ctx SpecContext, env map[string]string, baseImageEnv string, secrets map[string]string, expectedError string) {
			_, err := run(ctx, env, baseImageEnv, secrets)
			Expect(err).To(MatchError(ContainSubstring(expectedError)))
		},

		Entry("no source provides the version", nil, "", nil,
			`PACKAGES_VERSION: werf records it in the SBOM; set it in packages[].env, e.g. PACKAGES_VERSION: "%secret:PACKAGES_VERSION%"`),
		Entry("a declared secret the env does not reference", nil, "", map[string]string{"PACKAGES_VERSION": "3.0.0"},
			"set it in packages[].env"),
		Entry("the referenced secret file is missing", map[string]string{"PACKAGES_VERSION": "%secret:PACKAGES_VERSION%"}, "", nil,
			"PACKAGES_VERSION: No such file or directory"),
		Entry("the value is set but empty", map[string]string{"PACKAGES_VERSION": ""}, "", nil,
			"set it in packages[].env"),
		Entry("the referenced secret is empty", map[string]string{"PACKAGES_VERSION": "%secret:PACKAGES_VERSION%"}, "", map[string]string{"PACKAGES_VERSION": ""},
			"set it in packages[].env"),
	)

	It("fails the stage when a secret another variable references cannot be read", func(ctx SpecContext) {
		_, err := run(ctx, map[string]string{"PACKAGES_VERSION": "1.0.0", "REGISTRY": "%secret:REGISTRY%"}, "", nil)
		Expect(err).To(MatchError(ContainSubstring("REGISTRY: No such file or directory")))
	})
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
			substring: `cd "/app" && pip3 install --no-cache-dir -r "requirements.txt"`,
		}),
		Entry("PythonPip env is empty", backwardCompatEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{}},
			substring: `cd "/app" && pip3 install --no-cache-dir -r "requirements.txt"`,
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
			envPrefix: `GOPROXY=http://proxy:8080`,
		}),

		Entry("python-pip passes PIP_INDEX_URL", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://private-pypi"}},
			substring: "pip3 install",
			envPrefix: `PIP_INDEX_URL=http://private-pypi`,
		}),

		Entry("rust-cargo passes CARGO_NET_GIT_FETCH_WITH_CLI", nonOsPmEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}},
			substring: "cargo fetch",
			envPrefix: `CARGO_NET_GIT_FETCH_WITH_CLI=true`,
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
			Expect(cmds[0]).To(ContainSubstring(fmt.Sprintf("&& %s=%s %s", entry.envVarName, entry.envValue, entry.substring)))
		},

		Entry("GoMod with GOPROXY=direct", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"GOPROXY": "direct"}},
			substring:  `go mod download`,
			envVarName: "GOPROXY",
			envValue:   "direct",
		}),

		Entry("PythonUV with UV_EXTRA_INDEX_URL", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"UV_EXTRA_INDEX_URL": "http://pypi:8080"}},
			substring:  `uv sync --frozen`,
			envVarName: "UV_EXTRA_INDEX_URL",
			envValue:   "http://pypi:8080",
		}),

		Entry("PythonPip with PIP_INDEX_URL", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"PIP_INDEX_URL": "http://pypi:8080"}},
			substring:  `pip3 install --no-cache-dir -r "requirements.txt"`,
			envVarName: "PIP_INDEX_URL",
			envValue:   "http://pypi:8080",
		}),

		Entry("PythonPoetry with POETRY_HTTP_BASIC_MYREGISTRY_USERNAME", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypePythonPoetry, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"POETRY_HTTP_BASIC_MYREGISTRY_USERNAME": "user"}},
			substring:  `poetry sync --no-root`,
			envVarName: "POETRY_HTTP_BASIC_MYREGISTRY_USERNAME",
			envValue:   "user",
		}),

		Entry("RustCargo with CARGO_NET_RETRY", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"CARGO_NET_RETRY": "3"}},
			substring:  `cargo fetch`,
			envVarName: "CARGO_NET_RETRY",
			envValue:   "3",
		}),

		Entry("JavaScriptNpm with npm_config__authtoken", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"npm_config__authtoken": "token"}},
			substring:  `npm ci`,
			envVarName: "npm_config__authtoken",
			envValue:   "token",
		}),

		Entry("JavaScriptYarn with YARN_ENABLE_IMMUTABLE_INSTALLS", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"YARN_ENABLE_IMMUTABLE_INSTALLS": "false"}},
			substring:  `yarn install --frozen-lockfile`,
			envVarName: "YARN_ENABLE_IMMUTABLE_INSTALLS",
			envValue:   "false",
		}),

		Entry("JavaScriptPnpm with PNPM_HOME", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptPnpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"PNPM_HOME": "/custom/path"}},
			substring:  `pnpm install --frozen-lockfile`,
			envVarName: "PNPM_HOME",
			envValue:   "/custom/path",
		}),

		Entry("LuaRock with LUAROCKS_PROXY", langEnvVarEntry{
			directive:  &PackagesDirective{Type: PackagesDirectiveTypeLuaRock, FileBased: FileBasedSpec{Workdir: "/app", Spec: "rockspec"}, Env: map[string]string{"LUAROCKS_PROXY": "http://proxy:8080"}},
			substring:  `luarocks install --only-deps "rockspec"`,
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
			substring: `go mod download`,
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`&& A_VAR=a Z_VAR=z go mod download`)) },
			},
		}),

		Entry("PythonUV with two env vars sorted alphabetically", multiEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Spec: "pyproject.toml"}, Env: map[string]string{"BBB": "two", "AAA": "one"}},
			substring: `uv sync --frozen`,
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`&& AAA=one BBB=two uv sync`)) },
			},
		}),

		Entry("JavaScriptNpm with three env vars sorted alphabetically", multiEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"Z_LAST": "3", "M_MID": "2", "A_FIRST": "1"}},
			substring: `npm ci`,
			checks: []func(cmd string){
				func(cmd string) { Expect(cmd).To(ContainSubstring(`&& A_FIRST=1 M_MID=2 Z_LAST=3 npm ci`)) },
				func(cmd string) { Expect(cmd).To(ContainSubstring(`A_FIRST=1 M_MID=2 Z_LAST=3`)) },
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
			Expect(cmds[0]).To(ContainSubstring(fmt.Sprintf("&& HTTPS_PROXY=https://proxy:8443 HTTP_PROXY=http://proxy:8080 %s", entry.substring)))
		},

		Entry("GoMod with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeGoMod, FileBased: FileBasedSpec{Workdir: "/app", Spec: "go.mod"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `go mod download`,
		}),

		Entry("PythonPip with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypePythonPip, FileBased: FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `pip3 install --no-cache-dir -r "requirements.txt"`,
		}),

		Entry("RustCargo with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeRustCargo, FileBased: FileBasedSpec{Workdir: "/app", Spec: "Cargo.toml"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `cargo fetch`,
		}),

		Entry("JavaScriptNpm with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptNpm, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `npm ci`,
		}),

		Entry("JavaScriptYarn with HTTP_PROXY and HTTPS_PROXY", proxyEnvVarEntry{
			directive: &PackagesDirective{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json"}, Env: map[string]string{"HTTP_PROXY": "http://proxy:8080", "HTTPS_PROXY": "https://proxy:8443"}},
			substring: `yarn install --frozen-lockfile`,
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
