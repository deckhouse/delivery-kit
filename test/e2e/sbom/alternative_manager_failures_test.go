package e2e_build_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM alternative package manager failures", Label("e2e", "sbom", "alternative-manager-failure", "simple"), func() {
	type failureEntry struct {
		name           string
		fixture        string
		manager        string
		failureMarkers []string
		builderID      string
	}

	DescribeTable("preserves dependency installation diagnostics",
		func(ctx SpecContext, testOpts sbomTestOptions, entry failureEntry) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)

			repoDirname := "repo_sbom_" + entry.name + "_invalid_lock"
			SuiteData.InitTestRepo(ctx, repoDirname, "negative/"+entry.fixture)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, entry.builderID)
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					Envs:       builderEnv,
				},
			})

			Expect(out).To(SatisfyAny(
				ContainSubstring(entry.failureMarkers[0]),
				ContainSubstring(entry.failureMarkers[1]),
			), "expected %s bootstrap or dependency failure diagnostics; got:\n%s", entry.manager, out)
			if strings.Contains(out, entry.failureMarkers[1]) {
				Expect(out).To(SatisfyAny(
					ContainSubstring("lock"),
					ContainSubstring("frozen"),
				), "expected the original lock-related cause; got:\n%s", out)
			}
			Expect(out).NotTo(ContainSubstring(entry.manager + " cleanup failed"))
		},
		Entry("Yarn with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "yarn", fixture: "yarn_invalid_lock", manager: "yarn", failureMarkers: []string{"yarn bootstrap failed", "yarn dependency installation failed"}, builderID: "sbom-yarn-invalid-lock-builder",
		}),
		Entry("pnpm with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "pnpm", fixture: "pnpm_invalid_lock", manager: "pnpm", failureMarkers: []string{"pnpm bootstrap failed", "pnpm dependency installation failed"}, builderID: "sbom-pnpm-invalid-lock-builder",
		}),
		Entry("uv with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "uv", fixture: "uv_invalid_lock", manager: "uv", failureMarkers: []string{"uv bootstrap failed", "uv dependency installation failed"}, builderID: "sbom-uv-invalid-lock-builder",
		}),
		Entry("Poetry with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "poetry", fixture: "poetry_invalid_lock", manager: "poetry", failureMarkers: []string{"poetry bootstrap failed", "poetry dependency installation failed"}, builderID: "sbom-poetry-invalid-lock-builder",
		}),
	)

	DescribeTable("rejects a pre-installed alternative manager before bootstrap",
		func(ctx SpecContext, testOpts sbomTestOptions, entry failureEntry) {
			setupSbomBuildEnv(testOpts.setupEnvOptions)
			repoDirname := "repo_sbom_" + entry.name + "_preinstalled"
			SuiteData.InitTestRepo(ctx, repoDirname, "negative/"+entry.fixture)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)
			builderEnv := buildTrustedBuilderBase(ctx, testRepoPath, entry.builderID)
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			out := werfProject.Build(ctx, &werf.BuildOptions{CommonOptions: werf.CommonOptions{ShouldFail: true, Envs: builderEnv}})
			Expect(out).To(ContainSubstring(entry.manager + " must not be pre-installed"))
			Expect(out).NotTo(ContainSubstring(entry.manager + " bootstrap failed"))
			Expect(out).NotTo(ContainSubstring(entry.manager + " cleanup failed"))
		},
		Entry("Yarn", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "yarn", fixture: "yarn_preinstalled", manager: "yarn", builderID: "sbom-yarn-preinstalled-builder"}),
		Entry("pnpm", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "pnpm", fixture: "pnpm_preinstalled", manager: "pnpm", builderID: "sbom-pnpm-preinstalled-builder"}),
		Entry("uv", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "uv", fixture: "uv_preinstalled", manager: "uv", builderID: "sbom-uv-preinstalled-builder"}),
		Entry("Poetry", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "poetry", fixture: "poetry_preinstalled", manager: "poetry", builderID: "sbom-poetry-preinstalled-builder"}),
	)
})
