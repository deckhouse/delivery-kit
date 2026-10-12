package get

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("SBOM metadata repository", func() {
	ginkgo.It("accepts a separate metadata repository for image builds", func() {
		cmd := NewCmd(context.Background())
		gomega.Expect(cmd.ParseFlags([]string{"--repo=example.com/images", "--meta-repo=example.com/metadata"})).To(gomega.Succeed())
		address, err := commonCmdData.MetaRepo.GetAddress()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(address).To(gomega.Equal("example.com/metadata"))
	})
})
