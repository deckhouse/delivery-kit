package e2e_build_test

import (
	"strings"

	"github.com/werf/werf/v2/test/pkg/externalrefmock"
	"github.com/werf/werf/v2/test/pkg/suite_init"
)

type setupEnvOptions struct {
	ContainerBackendMode string
}

type sbomTestOptions struct {
	setupEnvOptions
}

func setupSbomBuildEnv(opts setupEnvOptions) {
	if opts.ContainerBackendMode == "docker" || strings.HasSuffix(opts.ContainerBackendMode, "-docker") {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", "docker")
	} else {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", opts.ContainerBackendMode)
	}

	if opts.ContainerBackendMode == "buildkit-docker" {
		SuiteData.Stubs.SetEnv("DOCKER_BUILDKIT", "1")
	} else {
		SuiteData.Stubs.UnsetEnv("DOCKER_BUILDKIT")
	}

	SuiteData.Stubs.SetEnv("WERF_REPO", suite_init.TestRepo(SuiteData.ProjectName))
	SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
	SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")
	SuiteData.Stubs.UnsetEnv("WERF_FORCE_STAGED_DOCKERFILE")
	SuiteData.Stubs.SetEnv("WERF_EXTERNAL_REFS_SERVER_URL", externalrefmock.Start().URL)
}
