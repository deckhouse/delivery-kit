package suite_init

import (
	"errors"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/test/pkg/contback"
	"github.com/werf/werf/v3/test/pkg/testresource"
)

func (data *SuiteData) SetupProjectCleanup() bool {
	return ginkgo.BeforeEach(func(ctx ginkgo.SpecContext) {
		projectName := data.ProjectName
		data.CleanupRepositories = nil
		tracker := testresource.Activate(ctx, projectName, data.WerfBinPath)
		ginkgo.DeferCleanup(func(ctx ginkgo.SpecContext) {
			resources, trackingErr := tracker.Finish(ctx)
			cleanupErr := contback.CleanupProject(ctx, projectName, contback.CleanupProjectOptions{
				Repositories:   append(resources.Repositories, data.CleanupRepositories...),
				Backends:       resources.Backends,
				DockerImageIDs: resources.DockerImageIDs,
			})
			gomega.Expect(errors.Join(trackingErr, cleanupErr)).To(gomega.Succeed())
		}, ginkgo.NodeTimeout(2*time.Minute))
	})
}
