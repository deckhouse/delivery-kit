package nativegate

import (
	"context"
	"os"
	"path/filepath"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("automatic source context", func() {
	ginkgo.It("declares mapped code and stage directories without recipe labels", func() {
		roots, err := UserSourceRoots(context.Background(), []string{"/src"}, "/build", "/tmp")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(roots).To(gomega.ConsistOf("/src", "/build", "/tmp"))
		directory := ginkgo.GinkgoT().TempDir()
		filename, err := MaterializeBuildContext(context.Background(), fixtureImage(nil), &PackageSet{}, directory, ContextOptions{Subject: "app", Platform: "linux/amd64", UserRoots: roots, ContainerRoot: "/.werf/sbom-build-context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(filename).To(gomega.Equal("/.werf/sbom-build-context/context.json"))
		body, err := os.ReadFile(filepath.Join(directory, "context.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared, err := buildcontext.Decode(body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declared.Subject.Source.Kind).To(gomega.Equal("declared"))
		gomega.Expect(declared.OwnRoots).To(gomega.ConsistOf(roots))
	})
	ginkgo.DescribeTable("does not declare system directories through WorkingDir", func(workdir string) {
		roots, err := UserSourceRoots(context.Background(), []string{"/src"}, workdir, "/tmp")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(roots).To(gomega.ConsistOf("/src", "/tmp"))
	}, ginkgo.Entry("root", "/"), ginkgo.Entry("headers", "/usr/include"), ginkgo.Entry("lib64", "/lib64"), ginkgo.Entry("optional packages", "/opt/project"))
	ginkgo.It("rejects root mapping instead of declaring the entire image", func() {
		_, err := UserSourceRoots(context.Background(), []string{"/"}, "/", "/tmp")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("root")))
	})
})
