package config

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("formatPackageEnvValue", func() {
	DescribeTable("keeps the secret out of the generated command",
		func(value, expected string) {
			Expect(formatPackageEnvValue(value)).To(Equal(expected))
		},
		Entry("secret content", "%secret:TOKEN%", `"$(</run/secrets/TOKEN)"`),
		Entry("secret path", "%secret_path:credentials%", "/run/secrets/credentials"),
		Entry("secret inside a larger value", "https://gitlab-ci-token:%secret:TOKEN%@example.com/", `https://gitlab-ci-token:"$(</run/secrets/TOKEN)"@example.com/`),
		Entry("two references", "%secret:A%:%secret:B%", `"$(</run/secrets/A)":"$(</run/secrets/B)"`),
		Entry("unknown namespace stays literal", "%env:TOKEN%", "%env:TOKEN%"),
		Entry("unterminated reference stays literal", "%secret:TOKEN", "%secret:TOKEN"),
		Entry("ordinary value", "http://proxy.example.com:8080", "http://proxy.example.com:8080"),
		Entry("empty value", "", "''"),
	)

	DescribeTable("resolves the reference at runtime",
		func(ctx SpecContext, value, expected string) {
			dir := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(dir, "TOKEN"), []byte("s3cret\n"), 0o600)).To(Succeed())

			assignment := strings.ReplaceAll(formatPackageEnvValue(value), packageSecretsDir, dir+"/")
			cmd := exec.CommandContext(ctx, "bash", "-ec", `SOME_VAR=`+assignment+`; printf '%s' "$SOME_VAR"`)
			stderr := &bytes.Buffer{}
			cmd.Stderr = stderr
			stdout, err := cmd.Output()
			Expect(err).NotTo(HaveOccurred(), stderr.String())
			Expect(string(stdout)).To(Equal(strings.ReplaceAll(expected, packageSecretsDir, dir+"/")))
		},
		Entry("secret content without its trailing newline", "%secret:TOKEN%", "s3cret"),
		Entry("secret path", "%secret_path:TOKEN%", "/run/secrets/TOKEN"),
		Entry("secret composed into a url", "https://gitlab-ci-token:%secret:TOKEN%@example.com/", "https://gitlab-ci-token:s3cret@example.com/"),
		Entry("unknown namespace stays literal", "%env:TOKEN%", "%env:TOKEN%"),
		Entry("shell construct stays literal", "$(echo pwned)", "$(echo pwned)"),
	)
})

var _ = Describe("validatePackageEnvValues", func() {
	rawPackages := func(value string) []*rawPackagesDirective {
		return []*rawPackagesDirective{{Type: "go-mod", Env: map[string]string{"GOPROXY": value}}}
	}
	declared := []Secret{{Id: "TOKEN"}}

	DescribeTable("rejects a reference the build cannot satisfy",
		func(value, message string) {
			err := validatePackageEnvValues(rawPackages(value), declared)
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("undeclared secret", "%secret:MISSING%", `packages[0].env["GOPROXY"] references secret "MISSING", which is not declared`),
		Entry("undeclared secret path", "%secret_path:MISSING%", `references secret "MISSING", which is not declared`),
		Entry("empty secret id", "%secret:%", `invalid secret id ""`),
		Entry("secret id with a space", "%secret:my token%", `invalid secret id "my token"`),
	)

	DescribeTable("accepts a valid value",
		func(value string) {
			Expect(validatePackageEnvValues(rawPackages(value), declared)).To(Succeed())
		},
		Entry("secret content", "%secret:TOKEN%"),
		Entry("secret path", "%secret_path:TOKEN%"),
		Entry("unknown namespace", "%env:MISSING%"),
		Entry("unterminated reference", "%secret:MISSING"),
		Entry("ordinary value", "direct"),
	)
})
