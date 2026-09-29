package e2e_build_test

import (
	"github.com/werf/werf/v3/test/pkg/externalrefmock"
	"github.com/werf/werf/v3/test/pkg/suite_init"
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
