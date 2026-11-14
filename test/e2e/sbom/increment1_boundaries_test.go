package e2e_build_test

import (
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
// one of pkg/build/sbom_native.go, pkg/sbom/nativegate and the checked exporter; the paths in the export refusals are those of the
// file in the checked image (/out for generated files, the git mapping /gen-src for git files) and are to be confirmed on the first run.
var _ = ginkgo.Describe("SBOM increment 1: checked images and service directories", ginkgo.Label("e2e", "sbom", "increment1"), func() {
	const exportPrefix = "verify export from checked image gen"

	type refusal struct {
		fixture string
		checked bool
		prepare func(repo string)
		wants   []string
	}
	refusals := map[string]refusal{
		"a checked image that is final":                      {fixture: "increment1/checked-final", checked: true, wants: []string{"checked image gen cannot be final"}},
		"a strict image built from a checked image":          {fixture: "increment1/checked-from", checked: true, wants: []string{"checked image gen cannot be used as from for strict image app"}},
		"an export of a git file changed in the checked one": {fixture: "increment1/checked-git-modified", checked: true, wants: []string{exportPrefix, "/gen-src/config.txt", "hash-mismatch: git original changed"}},
		"an export of an ELF without a record":               {fixture: "increment1/checked-elf", checked: true, prepare: prebuiltELF, wants: []string{exportPrefix, "/gen-src/tool", "missing sbom metadata"}},
		"an export of non-text data":                         {fixture: "increment1/checked-binary", checked: true, wants: []string{exportPrefix, "/out/blob.bin", "generated export must be non-executable text"}},
		"an export of a generated executable file":           {fixture: "increment1/checked-generated-exec", checked: true, wants: []string{exportPrefix, "/out/tool.sh", "generated export must be non-executable text"}},
		"an export of a git script with an ELF payload":      {fixture: "increment1/checked-script-elf", checked: true, wants: []string{exportPrefix, "/gen-src/run.sh", "unsupported binary format"}},
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
		// /app/config.h itself depends on a component marked generated, not just any generated component in the BOM.
		file, found := lo.Find(lo.FromPtr(bom.Components), func(component cdx.Component) bool { return component.Name == "/app/config.h" })
		gomega.Expect(found).To(gomega.BeTrue())
		dependency, found := lo.Find(lo.FromPtr(bom.Dependencies), func(dependency cdx.Dependency) bool { return dependency.Ref == file.BOMRef })
		gomega.Expect(found).To(gomega.BeTrue(), "no dependency entry for /app/config.h")
		generated := lo.Filter(lo.FromPtr(bom.Components), func(component cdx.Component, _ int) bool {
			return lo.Contains(lo.FromPtr(dependency.Dependencies), component.BOMRef) &&
				lo.ContainsBy(lo.FromPtr(component.Properties), func(property cdx.Property) bool {
					return property == cdx.Property{Name: "dk:verification", Value: "generated"}
				})
		})
		gomega.Expect(generated).NotTo(gomega.BeEmpty(), "/app/config.h does not depend on a generated component")
	})

	ginkgo.It("accepts a committed git script containing a BEL as text, owned by its Git component", func(ctx ginkgo.SpecContext) {
		stand := scratchStand()
		repo := i1Repo(ctx, "repo_sbom_i1_checked_script_bel", "increment1/checked-script-bel", stand, nil)
		SuiteData.Stubs.SetEnv("WERF_SBOM_CHECKED_IMAGES", "gen")
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		project.Build(ctx, &werf.BuildOptions{})
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}}}))
		file, found := lo.Find(lo.FromPtr(bom.Components), func(component cdx.Component) bool { return component.Name == "/app/run.sh" })
		gomega.Expect(found).To(gomega.BeTrue())
		// An export from a checked image is an image original; the Git identity stays on the owner component.
		gomega.Expect(lo.FromPtr(file.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "image"}))
		// dk:owner is the PURL of the owner component (state/contracts/dk-sbom.md), not its bom-ref.
		ownerPURL, found := lo.Find(lo.FromPtr(file.Properties), func(property cdx.Property) bool { return property.Name == "dk:owner" })
		gomega.Expect(found).To(gomega.BeTrue(), "/app/run.sh has no dk:owner")
		owner, found := lo.Find(lo.FromPtr(bom.Components), func(component cdx.Component) bool { return component.PackageURL == ownerPURL.Value })
		gomega.Expect(found).To(gomega.BeTrue(), "the owner component with the purl %s is not in the BOM", ownerPURL.Value)
		commit, found := lo.Find(lo.FromPtr(owner.Properties), func(property cdx.Property) bool { return property.Name == "dk:git-commit" })
		gomega.Expect(found).To(gomega.BeTrue(), "the owner of /app/run.sh carries no Git identity")
		gomega.Expect(commit.Value).NotTo(gomega.BeEmpty())
	})

	ginkgo.It("builds with an ssh agent socket mounted: the service placeholder is not a user file", func(ctx ginkgo.SpecContext) {
		stand := scratchStand()
		repo := i1Repo(ctx, "repo_sbom_i1_service_ssh_agent", "increment1/service-path-ssh-agent", stand, nil)
		startSSHAgent()
		werf.NewProject(SuiteData.WerfBinPath, repo).Build(ctx, &werf.BuildOptions{})
	})
})
