package common

import (
	"context"
	"os"

	ginkgo "github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/storage"
)

var _ = ginkgo.DescribeTable("GetSecondaryStagesStorageList reads the local repo automatically for a registry primary",
	func(primaryAddress string, secondaryRepos, expectedAddresses []string) {
		cmdData := secondaryTestCmdData(secondaryRepos)
		primaryStorage := &secondaryTestPrimaryStorage{address: primaryAddress}

		list, err := GetSecondaryStagesStorageList(context.Background(), primaryStorage, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(secondaryTestStorageAddresses(list)).To(gomega.Equal(expectedAddresses))
	},
	ginkgo.Entry("registry primary gets the local storage without asking for it", "registry.example.com/project", []string{}, []string{storage.LocalStorageAddress}),
	ginkgo.Entry("local primary without secondary repos gets no secondary storage", storage.LocalStorageAddress, []string{}, []string{}),
	ginkgo.Entry("explicit :local with a registry primary is not queried twice", "registry.example.com/project", []string{storage.LocalStorageAddress}, []string{storage.LocalStorageAddress}),
	ginkgo.Entry("explicit registry repos keep their order after the local storage", "registry.example.com/project", []string{"registry.example.com/second", "registry.example.com/first"}, []string{storage.LocalStorageAddress, "registry.example.com/second", "registry.example.com/first"}),
	ginkgo.Entry("explicit :local among registry repos stays the first one", "registry.example.com/project", []string{"registry.example.com/second", storage.LocalStorageAddress, "registry.example.com/first"}, []string{storage.LocalStorageAddress, "registry.example.com/second", "registry.example.com/first"}),
	ginkgo.Entry("explicit :local with a local primary is ignored", storage.LocalStorageAddress, []string{storage.LocalStorageAddress}, []string{}),
)

var _ = ginkgo.Describe("GetSecondaryStagesStorageList", func() {
	ginkgo.It("builds a local stages storage for a registry primary", func() {
		cmdData := secondaryTestCmdData([]string{storage.LocalStorageAddress})

		list, err := GetSecondaryStagesStorageList(context.Background(), &secondaryTestPrimaryStorage{address: "registry.example.com/project"}, &secondaryTestContainerBackend{}, cmdData)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(list).To(gomega.HaveLen(1))
		gomega.Expect(list[0]).To(gomega.BeAssignableToTypeOf(&storage.LocalStagesStorage{}))
	})

	ginkgo.It("does not duplicate the local storage requested through WERF_SECONDARY_REPO_1", func() {
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
