package e2e_vex_test

import (
	"runtime"
	"testing"

	"github.com/werf/werf/v2/test/pkg/suite_init"
)

func TestSuite(t *testing.T) {
	requiredTools := []string{"docker", "git"}
	suiteLabels := []string{suite_init.LabelNeedsRegistry}
	if runtime.GOOS == "linux" {
		requiredTools = append(requiredTools, "buildah")
		suiteLabels = append(suiteLabels, suite_init.LabelNeedsBuildah)
	}
	suite_init.MakeTestSuiteEntrypointFunc("E2E VEX suite", suite_init.TestSuiteEntrypointFuncOptions{
		RequiredSuiteTools: requiredTools,
		RequiredSuiteEnvs: []string{
			"WERF_TEST_K8S_DOCKER_REGISTRY",
		},
		SuiteLabels: suiteLabels,
	})(t)
}

var SuiteData = struct {
	suite_init.SuiteData
}{}

var (
	_ = SuiteData.SetupStubs(suite_init.NewStubsData())
	_ = SuiteData.SetupSynchronizedSuiteCallbacks(suite_init.NewSynchronizedSuiteCallbacksData())
	_ = SuiteData.SetupWerfBinary(suite_init.NewWerfBinaryData(SuiteData.SynchronizedSuiteCallbacksData))
	_ = SuiteData.SetupProjectName(suite_init.NewProjectNameData(SuiteData.StubsData))
	_ = SuiteData.SetupTmp(suite_init.NewTmpDirData())
)
