package e2e_sbom_validate_test

import (
	"testing"

	"github.com/werf/werf/v2/test/pkg/suite_init"
)

func TestSuite(t *testing.T) {
	suite_init.MakeTestSuiteEntrypointFunc("E2E SBOM validate suite", suite_init.TestSuiteEntrypointFuncOptions{
		RequiredSuiteTools: []string{"docker"},
	})(t)
}

var SuiteData = struct {
	suite_init.SuiteData
}{}

var (
	_ = SuiteData.SetupStubs(suite_init.NewStubsData())
	_ = SuiteData.SetupSynchronizedSuiteCallbacks(suite_init.NewSynchronizedSuiteCallbacksData())
	_ = SuiteData.SetupWerfBinary(suite_init.NewWerfBinaryData(SuiteData.SynchronizedSuiteCallbacksData))
	_ = SuiteData.SetupTmp(suite_init.NewTmpDirData())
)
