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

var _ = Describe("formatSecretVar", func() {
	It("generates a mounted-file fallback without embedding a value", func() {
		command := formatSecretVar("TOKEN")
		Expect(command).To(Equal(`TOKEN="${TOKEN-$([ -r /run/secrets/TOKEN ] && printf '%s' "$(</run/secrets/TOKEN)" || true)}"`))
		Expect(command).NotTo(ContainSubstring("secret-content"))
	})

	It("reads a mounted value at runtime", func(ctx SpecContext) {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "TOKEN"), []byte("from-file\n"), 0o600)).To(Succeed())
		fileCommand := strings.ReplaceAll(formatSecretVar("TOKEN"), packageSecretPathPrefix, dir+"/")
		cmd := exec.CommandContext(ctx, "bash", "-ec", fileCommand+`; printf '%s' "$TOKEN"`)
		cmd.Env = []string{"PATH="}
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		stdout, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred(), stderr.String())
		Expect(string(stdout)).To(Equal("from-file"))
	})
})

var _ = Describe("package secret references", func() {
	DescribeTable("formats declared and literal values without resolving them in Go",
		func(value string, declared bool, expected string) {
			options := PackagesCommandsOptions{}
			if declared {
				options.DeclaredSecretIDs = map[string]struct{}{"TOKEN": {}}
			}
			Expect(formatEnvVarsWithOptions(map[string]string{"TOKEN": value}, options)).To(Equal(expected))
		},
		Entry("declared reference", "/run/secrets/TOKEN", true, `TOKEN="$(</run/secrets/TOKEN)"`),
		Entry("undeclared reference", "/run/secrets/TOKEN", false, `TOKEN="/run/secrets/TOKEN"`),
		Entry("variable-like value", "${TOKEN}", true, `TOKEN="${TOKEN}"`),
		Entry("ordinary value", "literal", true, `TOKEN="literal"`),
		Entry("empty value", "", true, `TOKEN=""`),
	)

	It("formats repeated references without embedding their value", func() {
		options := PackagesCommandsOptions{DeclaredSecretIDs: map[string]struct{}{"TOKEN": {}}}
		command := formatEnvVarsWithOptions(map[string]string{
			"FIRST":  "/run/secrets/TOKEN",
			"SECOND": "/run/secrets/TOKEN",
		}, options)
		Expect(command).To(Equal(`FIRST="$(</run/secrets/TOKEN)" SECOND="$(</run/secrets/TOKEN)"`))
		Expect(command).NotTo(ContainSubstring("secret-content"))
	})
})
