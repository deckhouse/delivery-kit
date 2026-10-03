package common

import (
	"context"
	"os"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/storage"
)

var _ = ginkgo.DescribeTable("GetSecondaryStagesStorageList looks up the local repo only when it is requested explicitly",
	func(primaryAddress string, secondaryRepos, expectedAddresses []string) {
		cmdData := secondaryTestCmdData(secondaryRepos)
		primaryStorage := &secondaryTestPrimaryStorage{address: primaryAddress}

		list, err := GetSecondaryStagesStorageList(context.Background(), primaryStorage, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(secondaryTestStorageAddresses(list)).To(gomega.Equal(expectedAddresses))
	},
	ginkgo.Entry("registry primary without secondary repos gets no secondary storage", "registry.example.com/project", []string{}, []string{}),
	ginkgo.Entry("local primary without secondary repos gets no secondary storage", storage.LocalStorageAddress, []string{}, []string{}),
	ginkgo.Entry("explicit :local with a registry primary gets the local storage", "registry.example.com/project", []string{storage.LocalStorageAddress}, []string{storage.LocalStorageAddress}),
	ginkgo.Entry("explicit registry repos keep their order", "registry.example.com/project", []string{"registry.example.com/second", "registry.example.com/first"}, []string{"registry.example.com/second", "registry.example.com/first"}),
	ginkgo.Entry("explicit :local keeps its place among registry repos", "registry.example.com/project", []string{"registry.example.com/second", storage.LocalStorageAddress, "registry.example.com/first"}, []string{"registry.example.com/second", storage.LocalStorageAddress, "registry.example.com/first"}),
	ginkgo.Entry("explicit :local with a local primary is ignored", storage.LocalStorageAddress, []string{storage.LocalStorageAddress}, []string{}),
)

var _ = ginkgo.Describe("GetSecondaryStagesStorageList", func() {
	ginkgo.It("builds a local stages storage for an explicit :local repo", func() {
		cmdData := secondaryTestCmdData([]string{storage.LocalStorageAddress})

		list, err := GetSecondaryStagesStorageList(context.Background(), &secondaryTestPrimaryStorage{address: "registry.example.com/project"}, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(list).To(gomega.HaveLen(1))
		gomega.Expect(list[0]).To(gomega.BeAssignableToTypeOf(&storage.LocalStagesStorage{}))
	})

	ginkgo.It("accepts :local from WERF_SECONDARY_REPO_1", func() {
		cmdData := secondaryTestCmdData(nil)
		gomega.Expect(os.Setenv("WERF_SECONDARY_REPO_1", storage.LocalStorageAddress)).To(gomega.Succeed())
		ginkgo.DeferCleanup(func() {
			gomega.Expect(os.Unsetenv("WERF_SECONDARY_REPO_1")).To(gomega.Succeed())
		})

		list, err := GetSecondaryStagesStorageList(context.Background(), &secondaryTestPrimaryStorage{address: "registry.example.com/project"}, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(list).To(gomega.HaveLen(1))
		gomega.Expect(list[0]).To(gomega.BeAssignableToTypeOf(&storage.LocalStagesStorage{}))
	})

	ginkgo.It("rejects an empty secondary repo address", func() {
		cmdData := secondaryTestCmdData([]string{""})

		_, err := GetSecondaryStagesStorageList(context.Background(), &secondaryTestPrimaryStorage{address: "registry.example.com/project"}, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("--secondary-repo=ADDRESS param required")))
	})

	ginkgo.It("rejects an invalid secondary repo address", func() {
		cmdData := secondaryTestCmdData([]string{"REGISTRY.example.com/Project"})

		_, err := GetSecondaryStagesStorageList(context.Background(), &secondaryTestPrimaryStorage{address: "registry.example.com/project"}, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unable to create secondary stages storage in REGISTRY.example.com/Project")))
	})
})
