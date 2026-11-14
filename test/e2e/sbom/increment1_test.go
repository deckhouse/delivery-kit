package e2e_build_test

import (
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
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
var _ = ginkgo.Describe("SBOM increment 1: strict verification", ginkgo.Label("e2e", "sbom", "increment1"), func() {
	ginkgo.It("reuses an unchanged image and a cached install before rebuilding setup", func(ctx ginkgo.SpecContext) {
		stand := requireStand("BASE")
		repo := i1Repo(ctx, "repo_sbom_i1_cache", "increment1/cache", stand, nil)
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		first := project.Build(ctx, &werf.BuildOptions{})
		gomega.Expect(first).To(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(first).To(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED_v1"))
		repeated := project.Build(ctx, &werf.BuildOptions{})
		gomega.Expect(repeated).NotTo(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(repeated).NotTo(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED"))
		filename := filepath.Join(repo, "werf.yaml")
		body, err := os.ReadFile(filename)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		changed := strings.ReplaceAll(strings.ReplaceAll(string(body), "INCREMENT1_SETUP_EXECUTED_v1", "INCREMENT1_SETUP_EXECUTED_v2"), "setup-v1", "setup-v2")
		gomega.Expect(os.WriteFile(filename, []byte(changed), 0o644)).To(gomega.Succeed())
		utils.RunSucceedCommand(ctx, repo, "git", "add", "werf.yaml")
		utils.RunSucceedCommand(ctx, repo, "git", "commit", "-m", "change setup only")
		partial := project.Build(ctx, &werf.BuildOptions{})
		gomega.Expect(partial).NotTo(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(partial).To(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED_v2"))
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{}))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Name", "/app/install.marker")))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Name", "/app/setup.marker")))
	})
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
			reasons: []string{"missing"},
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
		"an arm64 file in an amd64 image": {
			fixture: "increment1/elf-in-git",
			needs:   []string{"BASE"},
			prepare: writeForeignELF("prebuilt/tool"),
			names:   []string{"/app/tool", "linux/arm64"},
			reasons: []string{"platform"},
		},
	}

	for title, tc := range cases {
		ginkgo.It("refuses "+title, func(ctx ginkgo.SpecContext) {
			stand := requireStand(tc.needs...)
			repo := i1Repo(ctx, "repo_sbom_i1_"+filepath.Base(tc.fixture)+"_"+hexPrefix(title), tc.fixture, stand, tc.prepare)
			for key, value := range tc.env {
				SuiteData.Stubs.SetEnv(key, stand.replace(value))
			}

			out := werf.NewProject(SuiteData.WerfBinPath, repo).Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{ShouldFail: true, ExtraArgs: tc.args},
			})

			for _, name := range tc.names {
				gomega.Expect(out).To(gomega.ContainSubstring(stand.replace(name)), "the refusal must name %s:\n%s", name, out)
			}
			for _, reason := range tc.reasons {
				gomega.Expect(out).To(gomega.ContainSubstring(reason), "the refusal must say %q:\n%s", reason, out)
			}
		})
	}

	ginkgo.It("builds a C and a Go binary on the instrumented builders, and the SBOM holds them as built files", func(ctx ginkgo.SpecContext) {
		stand := requireStand("BUILDER_NATIVE", "BUILDER_GO")
		repo := i1Repo(ctx, "repo_sbom_i1_positive", "increment1/positive", stand, nil)
		werfProject := werf.NewProject(SuiteData.WerfBinPath, repo)

		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"c-hello", "go-hello"}}})

		for _, image := range []string{"c-hello", "go-hello"} {
			bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{image}},
			}))
			gomega.Expect(bom.Components).NotTo(gomega.BeNil())
			file, found := lo.Find(*bom.Components, func(c cdx.Component) bool { return c.Name == "/app/hello" })
			gomega.Expect(found).To(gomega.BeTrue(), "%s: /app/hello must be a file component of the SBOM", image)
			origin, _ := lo.Find(lo.FromPtr(file.Properties), func(p cdx.Property) bool { return p.Name == "dk:origin" })
			gomega.Expect(origin.Value).To(gomega.Equal("build"), "%s: /app/hello is built by the instrumented chain", image)
			gomega.Expect(lo.FromPtr(bom.Metadata.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "instrumented-v1"}))
		}
	})
})
