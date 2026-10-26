package e2e_build_test

import (
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/test/pkg/report"
	sbomtest "github.com/werf/werf/v3/test/pkg/sbom"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

const (
	pmFilesJSONPath     = "/var/lib/pm/files.json"
	pmNoFileListWarning = "WARNING: /var/lib/pm/index.json is present but /var/lib/pm/files.json is not"
)

type pmFileList map[string]struct {
	Version  string            `json:"version"`
	Files    map[string]string `json:"files"`
	Symlinks map[string]string `json:"symlinks"`
}

var (
	// What `pm install curl==8.12.1 jq==1.8.1` on builder/distroless v3.1.16 installs,
	// the base image's own packages included.
	ospmInstalledPackages = []string{
		"baselayout", "brotli", "busybox", "c-ares", "curl", "findutils", "gnu-gcc-lib",
		"gnu-glibc-locale", "jq", "libc", "libidn2", "libpsl", "libstdc++", "libunistring",
		"nghttp2", "openssl", "rsync", "tzdata", "zstd",
	}
	ospmCurlDependencies = []string{"brotli", "c-ares", "libc", "libidn2", "libpsl", "libunistring", "nghttp2", "openssl", "zstd"}

	ospmShippedWithCurl = []string{"curl", "libc", "openssl", "brotli", "c-ares", "nghttp2", "libidn2", "libpsl", "zstd", "libunistring"}
	ospmLeftBehind      = []string{"jq", "gnu-gcc-lib", "libstdc++", "baselayout", "busybox", "tzdata", "rsync", "findutils", "gnu-glibc-locale"}
)

var _ = Describe("SBOM os-pm shipped scope", Label("e2e", "sbom", "ospm", "shipped-scope", "simple"), func() {
	It("records the files pm unpacked and finds them where the image holds them", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ospm_file_list"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_partial_import")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		reportProject := report.NewProjectWithReport(werfProject)
		buildOut, buildReport := reportProject.BuildWithReport(ctx,
			SuiteData.GetBuildReportPath("sbom_ospm_file_list.json"), nil,
		)
		Expect(buildOut).NotTo(ContainSubstring(pmNoFileListWarning),
			"the base image's pm records file lists, so werf has no reason to warn about a missing one")

		donorRecord, found := buildReport.Images["donor"]
		Expect(found).To(BeTrue(), "expected image %q in build report", "donor")
		donorRef := donorRecord.DockerRepo + "@" + donorRecord.DockerImageDigest

		By("installing with pm 0.1.12, the first pm that writes files.json")
		pmVersion, _, err := utils.RunCommandWithSeparateStreams(ctx, "", "docker",
			[]string{"run", "--rm", donorRef, "pm", "--version"}, utils.RunCommandOptions{ShouldSucceed: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(string(pmVersion))).To(Equal("0.1.12"))

		By("recording every installed package, dependencies included, with its files and symlinks")
		donorImg := pullImage(ctx, donorRef)
		var fileList pmFileList
		Expect(json.Unmarshal(readImageFile(donorImg, pmFilesJSONPath), &fileList)).To(Succeed())
		Expect(lo.Keys(fileList)).To(ConsistOf(ospmInstalledPackages))
		for _, pkg := range ospmCurlDependencies {
			Expect(fileList).To(HaveKey(pkg), "curl depends on %s, so installing curl installed it", pkg)
		}
		Expect(fileList["curl"].Version).To(Equal("8.12.1"))
		Expect(fileList["jq"].Version).To(Equal("1.8.1"))
		for name, entry := range fileList {
			Expect(entry.Version).NotTo(BeEmpty(), "%s has no version", name)
			Expect(entry.Files).NotTo(BeEmpty(), "%s has no files", name)
			Expect(entry.Symlinks).NotTo(BeNil(), "%s has no symlinks key", name)
			for file, digest := range entry.Files {
				Expect(file).To(HavePrefix("/"), "%s records %q, not an absolute path", name, file)
				Expect(digest).To(MatchRegexp(`^[0-9a-f]{64}$`), "%s records %q for %s, not a hex sha256", name, digest, file)
			}
		}
		Expect(fileList["curl"].Files).To(HaveKey("/usr/bin/curl"))
		Expect(fileList["curl"].Symlinks).To(HaveKeyWithValue("/usr/lib/libcurl.so.4", "libcurl.so.4.8.0"))
		Expect(fileList["jq"].Files).To(HaveKey("/usr/bin/jq"))

		By("recording the digest of the bytes the image holds")
		index, err := shippedscope.IndexImageFiles(ctx, donorImg)
		Expect(err).NotTo(HaveOccurred())
		for name, entry := range fileList {
			for file, digest := range entry.Files {
				held, ok := index.Files[file]
				if !ok {
					continue
				}
				Expect(held.Digest).To(Equal("sha256:"+digest), "%s records a digest for %s the image does not hold", name, file)
			}
		}
		Expect(index.Files["/usr/bin/curl"].Digest).To(Equal("sha256:" + fileList["curl"].Files["/usr/bin/curl"]))
		Expect(index.Files["/usr/bin/jq"].Digest).To(Equal("sha256:" + fileList["jq"].Files["/usr/bin/jq"]))

		// pm records the path the package archive spells, and these archives spell
		// /usr/lib64 and /lib64, which the base image points at /usr/lib: the file is
		// where the symlink leads, under the digest pm recorded.
		Expect(index.Symlinks).To(HaveKeyWithValue("/usr/lib64", "/usr/lib"))
		Expect(index.Symlinks).To(HaveKeyWithValue("/lib64", "/usr/lib"))
		Expect(fileList["openssl"].Files).To(HaveKey("/usr/lib64/libcrypto.so.3"))
		Expect(index.Files).NotTo(HaveKey("/usr/lib64/libcrypto.so.3"))
		Expect(index.Files["/usr/lib/libcrypto.so.3"].Digest).To(Equal("sha256:" + fileList["openssl"].Files["/usr/lib64/libcrypto.so.3"]))
		Expect(fileList["libc"].Files).To(HaveKey("/lib64/libc.so.6"))
		Expect(index.Files["/usr/lib/libc.so.6"].Digest).To(Equal("sha256:" + fileList["libc"].Files["/lib64/libc.so.6"]))

		By("writing the files as evidence on the donor's components, where the image holds them")
		donorBOM := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"donor"}},
		}))
		for _, pkg := range ospmInstalledPackages {
			comp := ospmComponent(donorBOM, pkg, "v3.1.16")
			Expect(comp).NotTo(BeNil(), "expected %s in the BOM of the image that installed it", pkg)
			Expect(comp.Version).To(Equal(fileList[pkg].Version), "%s is cataloged under a version other than the one pm installed", pkg)
			occurrences := occurrencesOf(comp)
			Expect(occurrences).NotTo(BeEmpty(), "%s is installed, so its files are in the image and must be its evidence", pkg)
			for _, occurrence := range occurrences {
				_, isFile := index.Files[occurrence.Location]
				_, isSymlink := index.Symlinks[occurrence.Location]
				Expect(isFile || isSymlink).To(BeTrue(), "%s has evidence at %s, which the image does not hold", pkg, occurrence.Location)
			}
			_, marked := shippedProperty(comp)
			Expect(marked).To(BeFalse(), "the image that installed %s holds its files, so it must not be marked", pkg)
		}

		curl := ospmComponent(donorBOM, "curl", "v3.1.16")
		Expect(occurrencesOf(curl)).To(ContainElements(
			cdx.EvidenceOccurrence{Location: "/usr/bin/curl", AdditionalContext: "sha256:" + fileList["curl"].Files["/usr/bin/curl"]},
			cdx.EvidenceOccurrence{Location: "/usr/lib/libcurl.so.4.8.0", AdditionalContext: "sha256:" + fileList["curl"].Files["/usr/lib/libcurl.so.4.8.0"]},
			cdx.EvidenceOccurrence{Location: "/usr/lib/libcurl.so.4", AdditionalContext: "symlink"},
		))

		openssl := ospmComponent(donorBOM, "openssl", "v3.1.16")
		Expect(occurrencesOf(openssl)).To(ContainElements(
			cdx.EvidenceOccurrence{Location: "/usr/lib/libcrypto.so.3", AdditionalContext: "sha256:" + fileList["openssl"].Files["/usr/lib64/libcrypto.so.3"]},
			cdx.EvidenceOccurrence{Location: "/usr/lib/libssl.so.3", AdditionalContext: "sha256:" + fileList["openssl"].Files["/usr/lib64/libssl.so.3"]},
		), "a file recorded under /usr/lib64 is evidence at /usr/lib, where the image holds it")
		Expect(lo.Map(occurrencesOf(openssl), locationOf)).NotTo(ContainElement(HavePrefix("/usr/lib64/")))
		Expect(occurrencesOf(ospmComponent(donorBOM, "libc", "v3.1.16"))).To(ContainElement(
			cdx.EvidenceOccurrence{Location: "/usr/lib/libc.so.6", AdditionalContext: "sha256:" + fileList["libc"].Files["/lib64/libc.so.6"]},
		))
	})

	It("marks the donor's packages none of whose files the importing image carries", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ospm_partial_import"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_partial_import")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})

		appBOMOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		})
		appBOM := sbomtest.MustParseSBOMOutput(appBOMOut)

		By("keeping every component of the donor in the importing image's BOM")
		for _, pkg := range ospmInstalledPackages {
			Expect(ospmComponent(appBOM, pkg, "v3.1.16")).NotTo(BeNil(),
				"%s was inherited from the donor and must stay in the BOM whether or not it shipped", pkg)
		}

		By("leaving unmarked a package the image carries a file of")
		for _, pkg := range ospmShippedWithCurl {
			_, marked := shippedProperty(ospmComponent(appBOM, pkg, "v3.1.16"))
			Expect(marked).To(BeFalse(), "a file of %s came along with curl, so it ships and must not be marked", pkg)
		}

		By("marking a package the image carries no file of")
		for _, pkg := range ospmLeftBehind {
			value, marked := shippedProperty(ospmComponent(appBOM, pkg, "v3.1.16"))
			Expect(marked).To(BeTrue(), "no file of %s came along, so it must be marked", pkg)
			Expect(value).To(Equal("false"), "%s", pkg)
		}

		By("producing the same BOM when the build comes from cache")
		rebuildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(rebuildOut).To(ContainSubstring("image app: Use previously generated SBOM from registry"))
		rebuiltBOMOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
			CommonOptions: werf.CommonOptions{ExtraArgs: []string{"app"}},
		})
		Expect(stableBOM(sbomtest.MustParseSBOMOutput(rebuiltBOMOut))).To(Equal(stableBOM(appBOM)),
			"a rebuild that changes nothing must carry the same verdicts")
	})

	It("leaves os-pm packages unjudged when the pm that installed them wrote no file list", func(ctx SpecContext) {
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_ospm_partial_import_no_filelist"
		SuiteData.InitTestRepo(ctx, repoDirname, "inject/ospm_partial_import_no_filelist")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(buildOut).To(ContainSubstring(pmNoFileListWarning),
			"the base image's pm writes index.json but no files.json, and werf must say so")

		for _, image := range []string{"donor", "app"} {
			bom := sbomtest.MustParseSBOMOutput(werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{ExtraArgs: []string{image}},
			}))

			jq := ospmComponent(bom, "jq", "v3.0.2")
			Expect(jq).NotTo(BeNil(), "expected jq in the BOM of %s", image)
			Expect(occurrencesOf(jq)).To(BeEmpty(), "no file list names the files of jq, so %s has no evidence for it", image)

			for _, comp := range lo.FromPtr(bom.Components) {
				if !strings.HasPrefix(comp.PackageURL, "pkg:generic/") {
					continue
				}
				_, marked := shippedProperty(&comp)
				Expect(marked).To(BeFalse(), "%s: nothing records where the files of %s@%s are, so nothing can say they are absent", image, comp.Name, comp.Version)
			}
		}
	})
})
