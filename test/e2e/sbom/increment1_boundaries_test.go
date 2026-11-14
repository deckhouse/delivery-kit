package e2e_build_test

import (
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/werf"
)

// Boundaries of the verification that need only the pm binary and a scratch base (WERF_TEST_I1_PM_BINARY, WERF_TEST_I1_PM_SHA256):
// checked build-environment images (WERF_SBOM_CHECKED_IMAGES=gen) and the /.werf service directories. The refusal wording is the
// one of pkg/build/sbom_native.go and pkg/sbom/nativegate; the exporter reasons of the checked producer that are not pinned yet are
// matched by the common prefix "verify export from checked image gen" and the fixture is the proof of the case.
var _ = ginkgo.Describe("SBOM increment 1: checked images and service directories", ginkgo.Label("e2e", "sbom", "increment1"), func() {
	const exportPrefix = "verify export from checked image gen"

	// scratchStand is the stand of these specs: the base is literal scratch, no index.
	scratchStand := func() *stand {
		s := requireStand()
		s.values["BASE"] = "scratch"
		return s
	}
	prebuiltELF := func(repo string) {
		gomega.Expect(os.MkdirAll(filepath.Join(repo, "prebuilt"), 0o755)).To(gomega.Succeed())
		writeStockELF("prebuilt/tool")(repo)
	}

	type refusal struct {
		fixture string
		checked bool
		prepare func(repo string)
		wants   []string
	}
	refusals := map[string]refusal{
		"a checked image that is final":                      {fixture: "increment1/checked-final", checked: true, wants: []string{"checked image gen cannot be final"}},
		"a strict image built from a checked image":          {fixture: "increment1/checked-from", checked: true, wants: []string{"checked image gen cannot be used as from for strict image app"}},
		"an export of a git file changed in the checked one": {fixture: "increment1/checked-git-modified", checked: true, wants: []string{exportPrefix, "hash-mismatch: git original changed"}},
		"an export of an ELF without a record":               {fixture: "increment1/checked-elf", checked: true, prepare: prebuiltELF, wants: []string{exportPrefix, "missing sbom metadata"}},
		"an export of non-text data":                         {fixture: "increment1/checked-binary", checked: true, wants: []string{exportPrefix}},
		"an export of a generated executable file":           {fixture: "increment1/checked-generated-exec", checked: true, wants: []string{exportPrefix}},
		"an export of a git script with an ELF payload":      {fixture: "increment1/checked-script-elf", checked: true, wants: []string{exportPrefix}},
		"a user file under /.werf/user":                      {fixture: "increment1/service-path-written", wants: []string{"/.werf/user/payload.txt: no-data: file has no trusted original"}},
		"a user file under /.werf/scripts":                   {fixture: "increment1/service-path-dir-scripts", wants: []string{"/.werf/scripts/payload.txt: no-data: file has no trusted original"}},
	}
	for title, tc := range refusals {
		ginkgo.It("refuses "+title, func(ctx ginkgo.SpecContext) {
			stand := scratchStand()
			repo := i1Repo(ctx, "repo_sbom_i1_"+filepath.Base(tc.fixture), tc.fixture, stand, tc.prepare)
			if tc.checked {
				SuiteData.Stubs.SetEnv("WERF_SBOM_CHECKED_IMAGES", "gen")
			}

			out := werf.NewProject(SuiteData.WerfBinPath, repo).Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ShouldFail: true}})

			for _, want := range tc.wants {
				gomega.Expect(out).To(gomega.ContainSubstring(want), "the refusal must name the reason:\n%s", out)
			}
		})
	}

	ginkgo.It("accepts generated text exported from a checked image and marks it generated", func(ctx ginkgo.SpecContext) {
		stand := scratchStand()
		repo := i1Repo(ctx, "repo_sbom_i1_checked_text", "increment1/checked-text", stand, nil)
		SuiteData.Stubs.SetEnv("WERF_SBOM_CHECKED_IMAGES", "gen")
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		project.Build(ctx, &werf.BuildOptions{})
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}}}))
		gomega.Expect(lo.FromPtr(bom.Metadata.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "instrumented-v1"}))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Properties", gomega.HaveValue(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "generated"})))))
	})

	ginkgo.It("accepts a committed git script containing a BEL as git text", func(ctx ginkgo.SpecContext) {
		stand := scratchStand()
		repo := i1Repo(ctx, "repo_sbom_i1_checked_script_bel", "increment1/checked-script-bel", stand, nil)
		SuiteData.Stubs.SetEnv("WERF_SBOM_CHECKED_IMAGES", "gen")
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		project.Build(ctx, &werf.BuildOptions{})
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}}}))
		file, found := lo.Find(lo.FromPtr(bom.Components), func(component cdx.Component) bool { return component.Name == "/app/run.sh" })
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(lo.FromPtr(file.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "git"}))
	})

	ginkgo.It("builds with an ssh agent socket mounted: the service placeholder is not a user file", func(ctx ginkgo.SpecContext) {
		stand := scratchStand()
		repo := i1Repo(ctx, "repo_sbom_i1_service_ssh_agent", "increment1/service-path-ssh-agent", stand, nil)
		startSSHAgent()
		werf.NewProject(SuiteData.WerfBinPath, repo).Build(ctx, &werf.BuildOptions{})
	})
})
