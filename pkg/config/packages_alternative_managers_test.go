package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func readPackagesCommandGolden(name string) string {
	contents, err := os.ReadFile(filepath.Join("..", "build", "stage", "testdata", "packages_commands", name))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(contents)
}

func normalizeAlternativeManagerScope(command string) string {
	return regexp.MustCompile(`/tmp/werf-packages-[0-9a-f-]+`).ReplaceAllString(command, "/tmp/werf-packages-UUID")
}

var _ = Describe("alternative manager lifecycle", func() {
	type entry struct {
		typeName   PackagesDirectiveType
		manager    string
		version    string
		install    string
		bootstrap  string
		primary    string
		workdir    string
		goldenFile string
	}

	DescribeTable("generates an isolated lifecycle for each manager", func(test entry) {
		command := GeneratePackagesCommands([]*PackagesDirective{{
			Type:      test.typeName,
			FileBased: FileBasedSpec{Workdir: test.workdir, Version: test.version},
		}})[0]

		Expect(strings.TrimSpace(normalizeAlternativeManagerScope(command))).To(Equal(strings.TrimSpace(readPackagesCommandGolden(test.goldenFile))))
		Expect(command).To(MatchRegexp(`(?s)^\nif command -v ` + test.manager + ` >/dev/null 2>&1; then\n  echo '` + test.manager + ` must not be pre-installed'`))
		Expect(command).To(ContainSubstring(`cd "` + test.workdir + `"`))
		Expect(command).To(ContainSubstring(`scope="/tmp/werf-packages-`))
		Expect(command).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
		Expect(command).To(ContainSubstring("/.werf/stapel/embedded/bin/mkdir -p \"$scope\""))
		Expect(command).To(ContainSubstring(test.primary))
		Expect(command).To(ContainSubstring(test.install))
		Expect(command).To(ContainSubstring(test.manager + `"` + test.install))
		Expect(command).To(ContainSubstring(test.version))
		Expect(command).To(ContainSubstring(test.bootstrap))
		Expect(command).To(ContainSubstring("/.werf/stapel/embedded/bin/rm -rf \"$scope\""))
		Expect(command).NotTo(ContainSubstring("mktemp"))
		Expect(command).NotTo(ContainSubstring("grep"))
		Expect(command).NotTo(ContainSubstring("set -e"))
		Expect(strings.Index(command, `cd "`+test.workdir+`"`)).To(BeNumerically("<", strings.Index(command, test.bootstrap)))
	},
		Entry("Yarn", entry{PackagesDirectiveTypeJavaScriptYarn, "yarn", "1.22.22", " install --frozen-lockfile", "npm install --prefix", "npm", "/app", "javascript-yarn.golden"}),
		Entry("pnpm", entry{PackagesDirectiveTypeJavaScriptPnpm, "pnpm", "9.15.4", " install --frozen-lockfile", "npm install --prefix", "npm", "/app", "javascript-pnpm.golden"}),
		Entry("uv", entry{PackagesDirectiveTypePythonUV, "uv", "0.8.17", " sync --frozen", "python3 -m venv", "pip", "/app", "python-uv.golden"}),
		Entry("Poetry", entry{PackagesDirectiveTypePythonPoetry, "poetry", "2.1.3", " sync --no-root", "python3 -m venv", "pip", "/app", "python-poetry.golden"}),
	)

	It("uses separate scopes and versions for multiple directives", func() {
		commands := GeneratePackagesCommands([]*PackagesDirective{
			{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/web", Version: "1.22.22"}},
			{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/api", Version: "0.8.17"}},
		})
		Expect(commands).To(HaveLen(2))
		Expect(commands[0]).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
		Expect(commands[1]).To(MatchRegexp(`scope="/tmp/werf-packages-[0-9a-f-]+"`))
		Expect(commands[0]).NotTo(Equal(commands[1]))
		Expect(commands[0]).To(ContainSubstring("1.22.22"))
		Expect(commands[1]).To(ContainSubstring("0.8.17"))
	})

	DescribeTable("rejects versions that are not exact semantic versions", func(typeName PackagesDirectiveType, version string) {
		directive := &PackagesDirective{Type: typeName, FileBased: FileBasedSpec{Workdir: "/app", Spec: "package.json", Version: version}}
		Expect(directive.validate()).To(MatchError(MatchRegexp("valid semantic version")))
	},
		Entry("Yarn range", PackagesDirectiveTypeJavaScriptYarn, "^1.22.22"),
		Entry("pnpm wildcard", PackagesDirectiveTypeJavaScriptPnpm, "9.x"),
		Entry("uv range", PackagesDirectiveTypePythonUV, ">=0.8.17"),
		Entry("Poetry whitespace", PackagesDirectiveTypePythonPoetry, " 2.1.3"),
	)

	It("accepts exact prerelease and build metadata", func() {
		for _, typeName := range []PackagesDirectiveType{
			PackagesDirectiveTypeJavaScriptYarn,
			PackagesDirectiveTypeJavaScriptPnpm,
			PackagesDirectiveTypePythonUV,
			PackagesDirectiveTypePythonPoetry,
		} {
			Expect((&PackagesDirective{Type: typeName, FileBased: FileBasedSpec{Workdir: "/app", Spec: "manifest", Version: "1.2.3-rc.1+build.7"}}).validate()).To(Succeed())
		}
	})

	DescribeTable("applies directive environment to external commands", func(typeName PackagesDirectiveType, version, command string) {
		generated := GeneratePackagesCommands([]*PackagesDirective{{
			Type:      typeName,
			FileBased: FileBasedSpec{Workdir: "/app", Version: version},
			Env:       map[string]string{"PACKAGE_INDEX": "https://packages.example"},
		}})[0]
		Expect(generated).To(ContainSubstring(`PACKAGE_INDEX="https://packages.example" ` + command))
	},
		Entry("Yarn bootstrap", PackagesDirectiveTypeJavaScriptYarn, "1.22.22", "npm install --prefix"),
		Entry("pnpm install", PackagesDirectiveTypeJavaScriptPnpm, "9.15.4", `"$scope/node_modules/.bin/pnpm"`),
		Entry("uv install", PackagesDirectiveTypePythonUV, "0.8.17", `"$scope/bin/uv"`),
		Entry("Poetry install", PackagesDirectiveTypePythonPoetry, "2.1.3", `"$scope/bin/poetry"`),
	)

	It("keeps cleanup after dependency installation", func() {
		command := GeneratePackagesCommands([]*PackagesDirective{{Type: PackagesDirectiveTypePythonUV, FileBased: FileBasedSpec{Workdir: "/app", Version: "0.8.17"}}})[0]
		Expect(strings.Index(command, `"$scope/bin/uv" sync --frozen`)).To(BeNumerically("<", strings.Index(command, `rm -rf "$scope"`)))
	})

	It("rejects a pre-installed manager before bootstrap", func() {
		command := GeneratePackagesCommands([]*PackagesDirective{{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Version: "1.22.22"}}})[0]
		check := "command -v yarn >/dev/null 2>&1"
		Expect(command).To(ContainSubstring(check))
		Expect(strings.Index(command, check)).To(BeNumerically("<", strings.Index(command, "npm install --prefix")))
		Expect(command).To(ContainSubstring("yarn must not be pre-installed"))
	})

	It("reports operation-specific failure diagnostics", func() {
		for _, entry := range []struct {
			typeName PackagesDirectiveType
			manager  string
			install  string
		}{
			{PackagesDirectiveTypeJavaScriptYarn, "yarn", `"$scope/node_modules/.bin/yarn" install --frozen-lockfile`},
			{PackagesDirectiveTypeJavaScriptPnpm, "pnpm", `"$scope/node_modules/.bin/pnpm" install --frozen-lockfile`},
			{PackagesDirectiveTypePythonUV, "uv", `"$scope/bin/uv" sync --frozen`},
			{PackagesDirectiveTypePythonPoetry, "poetry", `"$scope/bin/poetry" sync --no-root`},
		} {
			command := GeneratePackagesCommands([]*PackagesDirective{{Type: entry.typeName, FileBased: FileBasedSpec{Workdir: "/app", Version: "1.2.3"}}})[0]
			Expect(command).To(ContainSubstring(entry.install), entry.manager)
			Expect(command).To(ContainSubstring(entry.manager+" dependency installation failed"), entry.manager)
			Expect(command).To(ContainSubstring(entry.manager+" bootstrap failed"), entry.manager)
			Expect(command).To(ContainSubstring(entry.manager+" cleanup failed"), entry.manager)
		}
	})

	It("generates a UUID-scoped path rather than a predictable suffix", func() {
		command := GeneratePackagesCommands([]*PackagesDirective{{Type: PackagesDirectiveTypeJavaScriptYarn, FileBased: FileBasedSpec{Workdir: "/app", Version: "1.22.22"}}})[0]
		Expect(command).To(MatchRegexp(regexp.QuoteMeta(`scope="/tmp/werf-packages-`) + `[0-9a-f-]+"`))
	})
})
