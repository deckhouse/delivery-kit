package e2e_build_test

import (
	"archive/tar"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/build"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
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
	ginkgo.It("keeps build_dir and tmp_dir cache contents outside the image and SBOM", func(ctx ginkgo.SpecContext) {
		stand := requireStand()
		repo := i1Repo(ctx, "repo_sbom_i1_cache_mounts", "increment1/cache-mounts", stand, nil)
		reportPath := SuiteData.GetBuildReportPath("increment1-mounts.json")
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		project.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--platform=linux/amd64", "--save-build-report", "--build-report-path=" + reportPath}}})
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{}))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Name", "/app/output")))
		for _, component := range lo.FromPtr(bom.Components) {
			gomega.Expect(component.Name).NotTo(gomega.HavePrefix("/go-cache/"))
			gomega.Expect(component.Name).NotTo(gomega.HavePrefix("/tmp-cache/"))
		}
		report, err := build.LoadBuildReportFromFile(ctx, reportPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(report.Images).To(gomega.HaveKey("app"))
		ref, err := name.ParseReference(report.Images["app"].DockerImageName)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		img, err := remote.Image(ref, remote.WithContext(ctx))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		index, err := shippedscope.IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeFalse())
		gomega.Expect(index.Files).To(gomega.HaveKey("/app/output"))
		for filename := range index.Files {
			gomega.Expect(filename).NotTo(gomega.HavePrefix("/go-cache/"))
			gomega.Expect(filename).NotTo(gomega.HavePrefix("/tmp-cache/"))
		}
		layers, err := img.Layers()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, layer := range layers {
			reader, err := layer.Uncompressed()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			ginkgo.DeferCleanup(reader.Close)
			tarReader := tar.NewReader(reader)
			for {
				header, err := tarReader.Next()
				if err == io.EOF {
					break
				}
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				if header.Size > 0 {
					filename := path.Clean("/" + header.Name)
					gomega.Expect(filename).NotTo(gomega.HavePrefix("/go-cache/"))
					gomega.Expect(filename).NotTo(gomega.HavePrefix("/tmp-cache/"))
				}
			}
		}
	})
	ginkgo.It("reuses unchanged images and rebuilds only the changed setup chain", func(ctx ginkgo.SpecContext) {
		stand := requireStand()
		SuiteData.Stubs.SetEnv("WERF_TMP_DIR", ginkgo.GinkgoT().TempDir())
		repo := i1Repo(ctx, "repo_sbom_i1_cache", "increment1/cache", stand, nil)
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		reportPath := SuiteData.GetBuildReportPath("increment1-cache.json")
		options := &werf.BuildOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"--platform=linux/amd64", "--save-build-report", "--build-report-path=" + reportPath}}}
		first := project.Build(ctx, options)
		gomega.Expect(first).To(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(first).To(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED_v1"))
		gomega.Expect(first).To(gomega.ContainSubstring("INCREMENT1_STABLE_EXECUTED"))
		firstReport, err := build.LoadBuildReportFromFile(ctx, reportPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(firstReport.Images).To(gomega.HaveKey("app"))
		gomega.Expect(firstReport.Images).To(gomega.HaveKey("stable"))
		gomega.Expect(firstReport.Images["app"].Rebuilt).To(gomega.BeTrue())
		gomega.Expect(firstReport.Images["stable"].Rebuilt).To(gomega.BeTrue())
		gomega.Expect(firstReport.Images["app"].DockerImageDigest).NotTo(gomega.BeEmpty())
		gomega.Expect(firstReport.Images["stable"].DockerImageDigest).NotTo(gomega.BeEmpty())
		repeated := project.Build(ctx, options)
		gomega.Expect(repeated).NotTo(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(repeated).NotTo(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED"))
		gomega.Expect(repeated).NotTo(gomega.ContainSubstring("INCREMENT1_STABLE_EXECUTED"))
		gomega.Expect(repeated).To(gomega.ContainSubstring("image app: Use previously generated SBOM from registry"))
		gomega.Expect(repeated).To(gomega.ContainSubstring("image stable: Use previously generated SBOM from registry"))
		repeatedReport, err := build.LoadBuildReportFromFile(ctx, reportPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, name := range []string{"app", "stable"} {
			gomega.Expect(repeatedReport.Images).To(gomega.HaveKey(name))
			record := repeatedReport.Images[name]
			gomega.Expect(record.Rebuilt).To(gomega.BeFalse())
			gomega.Expect(record.DockerImageDigest).To(gomega.Equal(firstReport.Images[name].DockerImageDigest))
			for _, stg := range record.Stages {
				gomega.Expect(stg.Rebuilt).To(gomega.BeFalse(), "%s/%s", name, stg.Name)
			}
		}
		filename := filepath.Join(repo, "werf.yaml")
		body, err := os.ReadFile(filename)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		changed := strings.ReplaceAll(strings.ReplaceAll(string(body), "INCREMENT1_SETUP_EXECUTED_v1", "INCREMENT1_SETUP_EXECUTED_v2"), "setup-v1", "setup-v2")
		gomega.Expect(os.WriteFile(filename, []byte(changed), 0o644)).To(gomega.Succeed())
		utils.RunSucceedCommand(ctx, repo, "git", "add", "werf.yaml")
		utils.RunSucceedCommand(ctx, repo, "git", "commit", "-m", "change setup only")
		partial := project.Build(ctx, options)
		gomega.Expect(partial).NotTo(gomega.ContainSubstring("INCREMENT1_INSTALL_EXECUTED"))
		gomega.Expect(partial).To(gomega.ContainSubstring("INCREMENT1_SETUP_EXECUTED_v2"))
		gomega.Expect(partial).NotTo(gomega.ContainSubstring("INCREMENT1_STABLE_EXECUTED"))
		gomega.Expect(partial).To(gomega.ContainSubstring("image stable: Use previously generated SBOM from registry"))
		partialReport, err := build.LoadBuildReportFromFile(ctx, reportPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(partialReport.Images).To(gomega.HaveKey("app"))
		gomega.Expect(partialReport.Images).To(gomega.HaveKey("stable"))
		gomega.Expect(partialReport.Images["app"].Rebuilt).To(gomega.BeTrue())
		gomega.Expect(partialReport.Images["stable"].Rebuilt).To(gomega.BeFalse())
		gomega.Expect(partialReport.Images["app"].DockerImageDigest).NotTo(gomega.Equal(firstReport.Images["app"].DockerImageDigest))
		gomega.Expect(partialReport.Images["stable"].DockerImageDigest).To(gomega.Equal(firstReport.Images["stable"].DockerImageDigest))
		gomega.Expect(partialReport.Images["app"].Stages).To(gomega.ContainElement(gomega.And(gomega.HaveField("Name", "install"), gomega.HaveField("Rebuilt", false))))
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}}}))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Name", "/app/install.marker")))
		gomega.Expect(lo.FromPtr(bom.Components)).To(gomega.ContainElement(gomega.HaveField("Name", "/app/setup.marker")))
	})
	ginkgo.It("builds from literal scratch with a verified git file", func(ctx ginkgo.SpecContext) {
		stand := requireStand()
		SuiteData.Stubs.SetEnv("WERF_TMP_DIR", ginkgo.GinkgoT().TempDir())
		repo := i1Repo(ctx, "repo_sbom_i1_from_scratch", "increment1/from-scratch", stand, nil)
		project := werf.NewProject(SuiteData.WerfBinPath, repo)
		project.Build(ctx, &werf.BuildOptions{})
		bom := sbomtest.MustParseSBOMOutput(project.SbomGet(ctx, &werf.SbomGetOptions{CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}}}))
		file, found := lo.Find(lo.FromPtr(bom.Components), func(component cdx.Component) bool { return component.Name == "/app/config.txt" })
		gomega.Expect(found).To(gomega.BeTrue())
		gomega.Expect(lo.FromPtr(file.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:origin", Value: "git"}))
		gomega.Expect(lo.FromPtr(bom.Metadata.Properties)).To(gomega.ContainElement(cdx.Property{Name: "dk:verification", Value: "instrumented-v1"}))
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
		refusal string
	}

	cases := map[string]negative{
		"a package file replaced in a shell stage": {
			fixture: "increment1/pkg-file-replaced",
			needs:   []string{"BASE", "PM_PACKAGE", "PM_PACKAGE_FILE", "TRUSTED_INDEXES"},
			refusal: "verify image app: @PM_PACKAGE_FILE@: hash-mismatch: pm original changed",
		},
		"an ELF binary in git, with no record of its build": {
			fixture: "increment1/elf-in-git",
			needs:   []string{"BASE", "TRUSTED_INDEXES"},
			prepare: writeStockELF("prebuilt/tool"),
			refusal: "verify image app: /app/tool: no-data: missing sbom metadata",
		},
		"a file of a commit changed in a shell stage": {
			fixture: "increment1/git-file-edited",
			needs:   []string{"BASE", "TRUSTED_INDEXES"},
			refusal: "verify image app: /app/config.txt: hash-mismatch: git original changed",
		},
		"a package outside the trusted index": {
			fixture: "increment1/package-outside-index",
			needs:   []string{"BASE", "PM_PACKAGE", "OTHER_INDEX"},
			env:     map[string]string{"WERF_SBOM_TRUSTED_INDEXES": "@OTHER_INDEX@"},
			refusal: "@PM_PACKAGE@: no-data: package outside instrumented index",
		},
		"a base image without an instrumented SBOM": {
			fixture: "increment1/base-without-sbom",
			needs:   []string{"BASE_NO_SBOM"},
			refusal: `unable to get base image sbom with ref @BASE_NO_SBOM@: the image "@BASE_NO_SBOM@" must have an SBOM artifact attached`,
		},
		"an empty registry base without an instrumented SBOM": {
			fixture: "increment1/base-empty-without-sbom",
			needs:   []string{"BASE_NO_SBOM_EMPTY"},
			refusal: `unable to get base image sbom with ref @BASE_NO_SBOM_EMPTY@: the image "@BASE_NO_SBOM_EMPTY@" must have an SBOM artifact attached`,
		},
		"an arm64 file in an amd64 image": {
			fixture: "increment1/elf-in-git",
			needs:   []string{"BASE", "TRUSTED_INDEXES"},
			prepare: writeForeignELF("prebuilt/tool"),
			refusal: "verify image app: /app/tool: unsupported platform linux/arm64: expected linux/amd64",
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

			gomega.Expect(out).To(gomega.ContainSubstring(stand.replace(tc.refusal)), "the refusal must name the file or package with its reason:\n%s", out)
		})
	}

	ginkgo.It("builds a C and a Go binary on the instrumented builders, and the SBOM holds them as built files", func(ctx ginkgo.SpecContext) {
		stand := requireStand("BUILDER_NATIVE", "BUILDER_GO", "TRUSTED_INDEXES")
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
