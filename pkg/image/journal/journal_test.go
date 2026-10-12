package journal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestJournal(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Image journal")
}

var _ = ginkgo.Describe("Image journal", func() {
	ginkgo.It("records unique full IDs and rejects unknown entries", func(ctx ginkgo.SpecContext) {
		directory := ginkgo.GinkgoT().TempDir()
		id := strings.Repeat("a", 64)
		gomega.Expect(Record(ctx, directory, "sha256:"+id)).To(gomega.Succeed())
		gomega.Expect(Record(ctx, directory, id)).To(gomega.Succeed())
		ids, err := Read(ctx, directory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(ids).To(gomega.Equal([]string{id}))
		gomega.Expect(Record(ctx, directory, "../foreign")).NotTo(gomega.Succeed())
		gomega.Expect(os.WriteFile(filepath.Join(directory, "invalid"), nil, 0o600)).To(gomega.Succeed())
		_, err = Read(ctx, directory)
		gomega.Expect(err).To(gomega.HaveOccurred())
	})

	ginkgo.DescribeTable("does not accept an incomplete producer", func(recordFailure bool) {
		ctx := context.Background()
		directory := ginkgo.GinkgoT().TempDir()
		finish, err := Begin(ctx, directory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(Check(ctx, directory)).NotTo(gomega.Succeed())
		if recordFailure {
			gomega.Expect(Record(ctx, filepath.Join(directory, "missing"), strings.Repeat("b", 64))).NotTo(gomega.Succeed())
			gomega.Expect(finish()).NotTo(gomega.Succeed())
			gomega.Expect(Check(ctx, directory)).NotTo(gomega.Succeed())
		} else {
			gomega.Expect(finish()).To(gomega.Succeed())
			gomega.Expect(Check(ctx, directory)).To(gomega.Succeed())
		}
	}, ginkgo.Entry("active producer", false), ginkgo.Entry("failed record", true))
})
