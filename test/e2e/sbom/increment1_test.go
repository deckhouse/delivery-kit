package e2e_build_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

// Increment 1 of the instrumented SBOM chain: the negative scenarios of the spec (5.3, 5.4) and one
// positive build, against instrumented builders and a pinned instrumented pm index.
//
// The specs need a stand: instrumented images in a registry, the pm binary, the trusted indexes.
// They are skipped, with the missing variables named, when it is not configured; see
// _increment1/README.md. Fixtures hold @TOKEN@ placeholders that i1Repo replaces.
var _ = Describe("SBOM increment 1: strict verification", Label("e2e", "sbom", "increment1"), func() {
	// A refusal must name the file (or the package) and the reason. The reasons are the wording of
	// pkg/sbom/nativegate; a change of wording is a change of this table.
	type negative struct {
		fixture string
		args    []string
		env     map[string]string
		// prepare may add files to the repository before its first commit.
		prepare func(repo string)
		needs   []string
		names   []string
		reasons []string
	}

	cases := map[string]negative{
		"a package file replaced in a shell stage": {
			fixture: "increment1/pkg-file-replaced",
			needs:   []string{"BASE", "PM_PACKAGE", "PM_PACKAGE_FILE"},
			names:   []string{"@PM_PACKAGE_FILE@"},
			reasons: []string{"hash-mismatch"},
		},
		"an ELF binary in git, with no record of its build": {
			fixture: "increment1/elf-in-git",
			needs:   []string{"BASE"},
			prepare: writeStockELF("prebuilt/tool"),
			names:   []string{"/app/tool"},
			reasons: []string{"missing build record"},
		},
		"a file of a commit changed in a shell stage": {
			fixture: "increment1/git-file-edited",
			needs:   []string{"BASE"},
			names:   []string{"/app/config.txt"},
			reasons: []string{"hash-mismatch"},
		},
		"a package outside the trusted index": {
			fixture: "increment1/package-outside-index",
			needs:   []string{"BASE", "PM_PACKAGE", "OTHER_INDEX"},
			env:     map[string]string{"WERF_SBOM_TRUSTED_INDEXES": "@OTHER_INDEX@"},
			names:   []string{"@PM_PACKAGE@"},
			reasons: []string{"outside instrumented index"},
		},
		"a base image without an instrumented SBOM": {
			fixture: "increment1/base-without-sbom",
			needs:   []string{"BASE_NO_SBOM"},
			reasons: []string{"no-data", "SBOM"},
		},
		"a build for a platform the chain does not cover": {
			fixture: "increment1/positive",
			args:    []string{"--platform=linux/arm64", "c-hello"},
			needs:   []string{"BUILDER_NATIVE", "BUILDER_GO"},
			names:   []string{"linux/arm64"},
			reasons: []string{"platform"},
		},
	}

	for title, tc := range cases {
		It("refuses "+title, func(ctx SpecContext) {
			stand := requireStand(tc.needs...)
			repo := i1Repo(ctx, "repo_sbom_i1_"+filepath.Base(tc.fixture)+"_"+hexPrefix(title), tc.fixture, stand, tc.prepare)
			for key, value := range tc.env {
				SuiteData.Stubs.SetEnv(key, stand.replace(value))
			}

			out := werf.NewProject(SuiteData.WerfBinPath, repo).Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{ShouldFail: true, ExtraArgs: tc.args},
			})

			for _, name := range tc.names {
				Expect(out).To(ContainSubstring(stand.replace(name)), "the refusal must name %s:\n%s", name, out)
			}
			for _, reason := range tc.reasons {
				Expect(out).To(ContainSubstring(reason), "the refusal must say %q:\n%s", reason, out)
			}
		})
	}

	It("builds a C and a Go binary on the instrumented builders, and the SBOM holds them as built files", func(ctx SpecContext) {
		stand := requireStand("BUILDER_NATIVE", "BUILDER_GO")
		repo := i1Repo(ctx, "repo_sbom_i1_positive", "increment1/positive", stand, nil)
		werfProject := werf.NewProject(SuiteData.WerfBinPath, repo)

		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"c-hello", "go-hello"}}})

		for _, image := range []string{"c-hello", "go-hello"} {
			bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{image}},
			}))
			Expect(bom.Components).NotTo(BeNil())
			file, found := lo.Find(*bom.Components, func(c cdx.Component) bool { return c.Name == "/app/hello" })
			Expect(found).To(BeTrue(), "%s: /app/hello must be a file component of the SBOM", image)
			origin, _ := lo.Find(lo.FromPtr(file.Properties), func(p cdx.Property) bool { return p.Name == "dk:origin" })
			Expect(origin.Value).To(Equal("build"), "%s: /app/hello is built by the instrumented chain", image)
			Expect(lo.FromPtr(bom.Metadata.Properties)).To(ContainElement(cdx.Property{Name: "dk:verification", Value: "instrumented-v1"}))
		}
	})
})

// stand is the configuration of an increment 1 stand, read from WERF_TEST_I1_* variables.
type stand struct{ values map[string]string }

var standKeys = []string{"BASE", "BASE_NO_SBOM", "BUILDER_NATIVE", "BUILDER_GO", "PM_PACKAGE", "PM_PACKAGE_FILE", "OTHER_INDEX"}

// requireStand skips the spec unless every variable it needs is set, and the build environment
// (pm binary, trusted indexes) of the stand is complete.
func requireStand(needs ...string) *stand {
	GinkgoHelper()
	s := &stand{values: map[string]string{}}
	var missing []string
	for _, key := range append([]string{"PM_BINARY", "TRUSTED_INDEXES"}, needs...) {
		value := os.Getenv("WERF_TEST_I1_" + key)
		if value == "" {
			missing = append(missing, "WERF_TEST_I1_"+key)
		}
		s.values[key] = value
	}
	if len(missing) > 0 {
		Skip("increment 1 stand is not configured, missing " + strings.Join(missing, ", "))
	}
	for _, key := range standKeys {
		if value := os.Getenv("WERF_TEST_I1_" + key); value != "" {
			s.values[key] = value
		}
	}
	body, err := os.ReadFile(s.values["PM_BINARY"])
	Expect(err).NotTo(HaveOccurred(), "read the pm binary")
	sum := sha256.Sum256(body)

	setupSbomBuildEnv()
	SuiteData.Stubs.SetEnv("WERF_SBOM_PM_BINARY", s.values["PM_BINARY"])
	SuiteData.Stubs.SetEnv("WERF_SBOM_PM_SHA256", hex.EncodeToString(sum[:]))
	SuiteData.Stubs.SetEnv("WERF_SBOM_TRUSTED_INDEXES", s.values["TRUSTED_INDEXES"])
	return s
}

func (s *stand) replace(text string) string {
	for key, value := range s.values {
		text = strings.ReplaceAll(text, "@"+key+"@", value)
	}
	return text
}

// i1Repo copies a fixture, fills its placeholders, lets prepare add files and commits the result.
func i1Repo(ctx context.Context, dirname, fixture string, s *stand, prepare func(repo string)) string {
	GinkgoHelper()
	repo := SuiteData.GetTestRepoPath(dirname)
	utils.CopyIn(utils.FixturePath(fixture), repo)
	Expect(filepath.WalkDir(repo, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Base(path) != "werf.yaml" {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(path, []byte(s.replace(string(body))), 0o644)
	})).To(Succeed())
	if prepare != nil {
		prepare(repo)
	}
	utils.RunSucceedCommand(ctx, repo, "git", "init")
	utils.RunSucceedCommand(ctx, repo, "git", "add", ".")
	utils.RunSucceedCommand(ctx, repo, "git", "commit", "-m", "initial")
	return repo
}

// writeStockELF builds a Linux ELF with the stock Go toolchain: an executable nothing recorded
// the build of, which is what a prebuilt binary committed to git is.
func writeStockELF(relPath string) func(repo string) {
	return func(repo string) {
		GinkgoHelper()
		work := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(work, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(work, "go.mod"), []byte("module prebuilt\n\ngo 1.22\n"), 0o644)).To(Succeed())
		command := exec.Command("go", "build", "-o", filepath.Join(repo, relPath), ".")
		command.Dir = work
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		out, err := command.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), string(out))
	}
}

func hexPrefix(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:3])
}
