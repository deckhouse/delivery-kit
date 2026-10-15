package suite_init

import (
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image/journal"
	"github.com/werf/werf/v3/test/pkg/contback"
	"github.com/werf/werf/v3/test/pkg/testresource"
)

func (data *SuiteData) SetupProjectCleanup() bool {
	return ginkgo.BeforeEach(func(ctx ginkgo.SpecContext) {
		projectName := data.ProjectName
		data.CleanupRepositories = nil
		directory := ginkgo.GinkgoT().TempDir()
		for _, backend := range []string{"docker", "buildah"} {
			gomega.Expect(os.Mkdir(filepath.Join(directory, backend), 0o700)).To(gomega.Succeed())
		}
		data.Stubs.SetEnv(journal.Env, directory)
		tracker := testresource.Activate(ctx, projectName, data.WerfBinPath)
		ginkgo.DeferCleanup(func(ctx ginkgo.SpecContext) {
			resources, trackingErr := tracker.Finish(ctx)
			gomega.Expect(trackingErr).NotTo(gomega.HaveOccurred())
			cleanupErr := contback.CleanupProject(ctx, projectName, contback.CleanupProjectOptions{
				Repositories:   append(resources.Repositories, data.CleanupRepositories...),
				Backends:       resources.Backends,
				DockerImageIDs: resources.DockerImageIDs,
			})
			gomega.Expect(cleanupErr).To(gomega.Succeed())
		}, ginkgo.NodeTimeout(2*time.Minute))
	})
}
