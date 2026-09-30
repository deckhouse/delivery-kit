package e2e_build_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/oci/artifact"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/utils"
	"github.com/werf/werf/v3/test/pkg/werf"
)

// Base images the sbom_caching fixture states are pinned to: state0 and state1
// build from the first one, state2 switches to the second.
var sbomCachingUpstreamBaseImageRefs = []string{
	"registry.deckhouse.io/container-factory@sha256:b9ebf99d849cc88889ee2281f8a9100fdeee4b95b11c4a0350f38135a835f5d1",
	"registry.deckhouse.io/container-factory@sha256:7aac8d97a91ac233b19111aaad9d7bba12b975e620cfa9287b97e0003e4d0a71",
}

var _ = Describe("SBOM caching (build.sbom.enable)", Label("e2e", "sbom", "caching"), func() {
	It("should invalidate stage cache when SBOM is enabled", func(ctx SpecContext) {
		By("initializing")
		setupSbomBuildEnv()

		repoDirname := "repo_sbom_caching"
		fixtureRelPath := "sbom_caching/state0"

		// The spec drops the base image from the local container storage to
		// exercise the pull path, so it must own that image: dropping the shared
		// upstream one breaks every other spec building from it in parallel.
		baseImageRefs := publishPrivateSbomCachingBaseImages(ctx)
		lastBaseImageRef := baseImageRefs[sbomCachingUpstreamBaseImageRefs[1]]

		By("first build without build.sbom.enable (default) - stages are cached without SBOM")
		SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
		useSbomCachingBaseImages(ctx, repoDirname, baseImageRefs)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
		buildOut := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(buildOut).To(ContainSubstring("Building stage"))
		Expect(buildOut).NotTo(ContainSubstring("Use previously built image"))

		By("rebuild without build.sbom.enable - existing cache is reused")
		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))

		By("build.sbom.enable=false - backward compatible, existing cache reused")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state1")
		useSbomCachingBaseImages(ctx, repoDirname, baseImageRefs)

		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))

		By("build.sbom.enable=true - stage cache is invalidated, stages rebuilt with SBOM")
		SuiteData.UpdateTestRepo(ctx, repoDirname, "sbom_caching/state2")
		useSbomCachingBaseImages(ctx, repoDirname, baseImageRefs)

		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		Expect(buildOut).To(ContainSubstring("Building stage"))

		By("rebuild with build.sbom.enable=true - cache is reused")
		removeOut, err := utils.RunCommand(ctx, testRepoPath, "docker", "image", "rm", lastBaseImageRef)
		if err != nil {
			Expect(string(removeOut)).To(ContainSubstring("No such image"))
		}
		buildOut = werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{}})
		// logboek truncates long process titles, so only the repository part of the
		// reference is guaranteed to be printed.
		lastBaseImageRepo, _, _ := strings.Cut(lastBaseImageRef, "@")
		Expect(buildOut).To(ContainSubstring("Pulling base image " + lastBaseImageRepo + "@"))
		Expect(buildOut).To(ContainSubstring("Use previously built image"))
		Expect(buildOut).NotTo(ContainSubstring("Building stage"))
	})
})

// publishPrivateSbomCachingBaseImages copies every upstream base image of the
// fixture, together with its attached SBOM, into a spec-private repository of
// the test registry and maps the upstream reference to the copy. The upstream
// images are also pulled into the local storage on purpose: they keep the
// layers shared with the copies referenced, so removing a copy cannot delete
// content other specs are pushing.
func publishPrivateSbomCachingBaseImages(ctx SpecContext) map[string]string {
	privateRepo := fmt.Sprintf("%s/%s-base", suite_init.TestRegistry(), SuiteData.ProjectName)
	remoteOpts := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}

	refs := make(map[string]string, len(sbomCachingUpstreamBaseImageRefs))
	for _, upstreamRef := range sbomCachingUpstreamBaseImageRefs {
		upstreamRepo, upstreamDigest, found := strings.Cut(upstreamRef, "@")
		Expect(found).To(BeTrue(), "upstream base image %q is not pinned by digest", upstreamRef)
		privateRef := privateRepo + "@" + upstreamDigest

		utils.RunSucceedCommand(ctx, "", "docker", "pull", upstreamRef)
		Expect(crane.Copy(upstreamRef, privateRef, crane.WithContext(ctx), crane.Insecure)).To(Succeed())
		Expect(artifact.CopyAttachedArtifacts(ctx, upstreamRepo, upstreamDigest, privateRepo, upstreamDigest, remoteOpts...)).To(Succeed())

		DeferCleanup(func(ctx SpecContext) {
			_, _ = utils.RunCommand(ctx, "", "docker", "image", "rm", privateRef)
		})

		refs[upstreamRef] = privateRef
	}

	return refs
}

func useSbomCachingBaseImages(ctx SpecContext, repoDirname string, baseImageRefs map[string]string) {
	testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
	configPath := filepath.Join(testRepoPath, "werf.yaml")

	configBytes, err := os.ReadFile(configPath)
	Expect(err).ShouldNot(HaveOccurred())
	config := string(configBytes)

	replaced := config
	for upstreamRef, privateRef := range baseImageRefs {
		replaced = strings.ReplaceAll(replaced, upstreamRef, privateRef)
	}
	Expect(replaced).NotTo(Equal(config), "fixture werf.yaml references none of the known upstream base images")

	utils.WriteFile(configPath, []byte(replaced))
	utils.RunSucceedCommand(ctx, testRepoPath, "git", "add", "werf.yaml")
	utils.RunSucceedCommand(ctx, testRepoPath, "git", "commit", "-m", "use spec-private base images")
}
