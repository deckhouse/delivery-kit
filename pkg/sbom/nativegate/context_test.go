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
	ginkgo.It("keeps a moved package header in the helper package mapping", func() {
		set := fixturePackageSet("/usr/include/sdk.h")
		directory := ginkgo.GinkgoT().TempDir()
		_, err := MaterializeBuildContext(context.Background(), fixtureImage(map[string][]byte{"/src/sdk.h": []byte("original")}), set, directory, ContextOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, ContainerRoot: "/.werf/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		body, err := os.ReadFile(filepath.Join(directory, "context.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared, err := buildcontext.Decode(body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declared.Imports).To(gomega.HaveLen(1))
		gomega.Expect(declared.Imports[0].Path).To(gomega.Equal("/src/sdk.h"))
		gomega.Expect(declared.Imports[0].OriginalPath).To(gomega.Equal("usr/include/sdk.h"))
	})
	ginkgo.It("binds an imported header to its original package path", func() {
		set := fixturePackageSet("/src/sdk.h")
		directory := ginkgo.GinkgoT().TempDir()
		_, err := MaterializeBuildContext(context.Background(), fixtureImage(map[string][]byte{"/src/sdk.h": []byte("original")}), set, directory, ContextOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, ContainerRoot: "/.werf/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		data, err := os.ReadFile(filepath.Join(directory, "context.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared, err := buildcontext.Decode(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declared.Imports).To(gomega.HaveLen(1))
		gomega.Expect(declared.Imports[0].Path).To(gomega.Equal("/src/sdk.h"))
		gomega.Expect(declared.Imports[0].OriginalPath).To(gomega.Equal("usr/include/sdk.h"))
	})
	ginkgo.It("rejects a modified package header inside a user root before compilation", func() {
		_, err := MaterializeBuildContext(context.Background(), fixtureImage(map[string][]byte{"/src/sdk.h": []byte("changed")}), fixturePackageSet("/src/sdk.h"), ginkgo.GinkgoT().TempDir(), ContextOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, ContainerRoot: "/.werf/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/sdk.h"), gomega.ContainSubstring("hash-mismatch"))))
	})
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
