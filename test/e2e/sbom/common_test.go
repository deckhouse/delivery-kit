package e2e_build_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"

	"github.com/werf/werf/v3/test/pkg/externalrefmock"
	"github.com/werf/werf/v3/test/pkg/suite_init"
	"github.com/werf/werf/v3/test/pkg/utils"
)

func setupSbomBuildEnv() {
	SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", "docker")
	SuiteData.Stubs.UnsetEnv("DOCKER_BUILDKIT")
	SuiteData.Stubs.SetEnv("WERF_REPO", suite_init.TestRepo(SuiteData.ProjectName))
	SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
	SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")
	SuiteData.Stubs.UnsetEnv("WERF_FORCE_STAGED_DOCKERFILE")
	SuiteData.Stubs.SetEnv("WERF_EXTERNAL_REFS_SERVER_URL", externalrefmock.Start().URL)
}

func buildTrustedBuilderBase(ctx SpecContext, testRepoPath, refSlug string) []string {
	builderBaseRef := fmt.Sprintf("%s/%s:test", suite_init.TestRegistry(), refSlug)
	utils.RunSucceedCommand(ctx, testRepoPath, "docker", "build", "-t", builderBaseRef, "-f", "Dockerfile.builder-base", ".")
	utils.RunSucceedCommand(ctx, testRepoPath, "docker", "push", builderBaseRef)
	return []string{
		fmt.Sprintf("BUILDER_BASE_IMAGE=%s", builderBaseRef),
		"WERF_E2E_ALLOW_LOCAL_BUILDER_IMAGES=true",
	}
}
