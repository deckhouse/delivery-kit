package e2e_build_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("Build with os-pm packages SBOM", Label("e2e", "build", "sbom", "packages"), func() {
	DescribeTable("should include pm-collected binary packages in the image SBOM",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_os_pm_packages"
			fixtureRelPath := "sbom/packages/state0"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			By("building and pushing trusted builder-base image to local registry")
			builderBaseRef := fmt.Sprintf("%s/os-pm-builder:test", suite_init.TestRegistry())
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build", "-t", builderBaseRef, "-f", "Dockerfile.builder-base", ".")
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", builderBaseRef)
			builderBaseEnv := []string{fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef)}

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			buildOut := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{Envs: builderBaseEnv},
			})
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))

			By("retrieving the image SBOM from the registry")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderBaseEnv,
				},
			})
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-app@9.9.9"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-lib@2.0.0"))
		},
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should merge pm-collected packages with the base image SBOM",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_os_pm_packages_base"
			fixtureRelPath := "sbom/packages/state1"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			By("building and pushing trusted builder-base image to local registry")
			builderBaseRef := fmt.Sprintf("%s/os-pm-builder:test", suite_init.TestRegistry())
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build", "-t", builderBaseRef, "-f", "Dockerfile.builder-base", ".")
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", builderBaseRef)
			builderBaseEnv := []string{fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef)}

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			buildOut := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{Envs: builderBaseEnv},
			})
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))

			By("retrieving the image SBOM from the registry")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderBaseEnv,
				},
			})
			Expect(sbomOut).To(ContainSubstring("pkg:generic/base-pkg@1.0.0"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-app@9.9.9"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-lib@2.0.0"))
		},
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)

	DescribeTable("should propagate parent fromImage pm packages into the child image SBOM",
		func(ctx SpecContext, testOpts simpleTestOptions) {
			By("initializing")
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo_os_pm_packages_propagation"
			fixtureRelPath := "sbom/packages/state2"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			By("building and pushing trusted builder-base image to local registry")
			builderBaseRef := fmt.Sprintf("%s/os-pm-builder:test", suite_init.TestRegistry())
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build", "-t", builderBaseRef, "-f", "Dockerfile.builder-base", ".")
			utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", builderBaseRef)
			builderBaseEnv := []string{fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef)}

			By("building images")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)
			buildOut := werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{Envs: builderBaseEnv},
			})
			Expect(buildOut).To(ContainSubstring(sbomProcessingPrefix))

			By("retrieving the child image SBOM from the registry")
			sbomOut := werfProject.SbomGet(ctx, &werf.SbomGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"app"},
					Envs:      builderBaseEnv,
				},
			})

			By("asserting the parent-installed os-pm packages propagated into the child SBOM")
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-app@9.9.9"))
			Expect(sbomOut).To(ContainSubstring("pkg:generic/demo-lib@2.0.0"))
		},
		Entry("with local repo using Vanilla Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with chroot isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-chroot",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		XEntry("with local repo using Native Buildah with rootless isolation", simpleTestOptions{setupEnvOptions{
			ContainerBackendMode:        "native-rootless",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)
})
