package e2e_build_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("SBOM alternative package manager failures", Label("e2e", "sbom", "alternative-manager-failure", "simple"), func() {
	type failureEntry struct {
		name      string
		fixture   string
		manager   string
		project   string
		builderID string
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
				ContainSubstring(entry.manager),
				ContainSubstring("lock"),
				ContainSubstring("frozen"),
			), "expected %s dependency failure diagnostics; got:\n%s", entry.manager, out)
			Expect(out).To(ContainSubstring(entry.manager))
			Expect(out).NotTo(ContainSubstring("cleanup"))
		},
		Entry("Yarn with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "yarn", fixture: "yarn_invalid_lock", manager: "yarn", project: "werf-test-e2e-sbom-yarn-simple", builderID: "sbom-yarn-invalid-lock-builder",
		}),
		Entry("pnpm with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "pnpm", fixture: "pnpm_invalid_lock", manager: "pnpm", project: "werf-test-e2e-sbom-pnpm-simple", builderID: "sbom-pnpm-invalid-lock-builder",
		}),
		Entry("uv with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "uv", fixture: "uv_invalid_lock", manager: "uv", project: "werf-test-e2e-sbom-python-uv-simple", builderID: "sbom-uv-invalid-lock-builder",
		}),
		Entry("Poetry with Vanilla Docker", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{
			name: "poetry", fixture: "poetry_invalid_lock", manager: "poetry", project: "werf-test-e2e-sbom-python-poetry-simple", builderID: "sbom-poetry-invalid-lock-builder",
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
			Expect(out).NotTo(ContainSubstring("bootstrap failed"))
			Expect(out).NotTo(ContainSubstring("cleanup failed"))
		},
		Entry("Yarn", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "yarn", fixture: "yarn_preinstalled", manager: "yarn", project: "", builderID: "sbom-yarn-preinstalled-builder"}),
		Entry("pnpm", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "pnpm", fixture: "pnpm_preinstalled", manager: "pnpm", project: "", builderID: "sbom-pnpm-preinstalled-builder"}),
		Entry("uv", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "uv", fixture: "uv_preinstalled", manager: "uv", project: "", builderID: "sbom-uv-preinstalled-builder"}),
		Entry("Poetry", sbomTestOptions{setupEnvOptions{ContainerBackendMode: "vanilla-docker"}}, failureEntry{name: "poetry", fixture: "poetry_preinstalled", manager: "poetry", project: "", builderID: "sbom-poetry-preinstalled-builder"}),
	)
})
