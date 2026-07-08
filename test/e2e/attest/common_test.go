package e2e_attest_test

import (
	"strings"

	"github.com/werf/werf/v2/test/pkg/suite_init"
)

func setupAttestEnv(containerBackendMode string) {
	if containerBackendMode == "docker" || strings.HasSuffix(containerBackendMode, "-docker") {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", "docker")
	} else {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", containerBackendMode)
	}

	if containerBackendMode == "buildkit-docker" {
		SuiteData.Stubs.SetEnv("DOCKER_BUILDKIT", "1")
	} else {
		SuiteData.Stubs.UnsetEnv("DOCKER_BUILDKIT")
	}

	SuiteData.Stubs.SetEnv("WERF_REPO", suite_init.TestRepo(SuiteData.ProjectName))
	SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
	SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")
	SuiteData.Stubs.UnsetEnv("WERF_FORCE_STAGED_DOCKERFILE")
}
