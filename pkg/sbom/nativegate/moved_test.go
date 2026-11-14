package nativegate

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// Spec 3.2: a package file moved or renamed in a shell stage is matched to the originals by
// content. Exactly one original with those bytes accounts for it under its package; none or
// several refuse the file by name.
var _ = ginkgo.Describe("moved package files", func() {
	const content = "package data"
	var opts VerifyOptions
	original := func(path, body string) Original {
		return Original{Path: path, SHA256: fixtureDigest([]byte(body)), Component: fixtureComponent("pm"), Kind: "pm"}
	}
	fileOrigin := func(bom *cdx.BOM, name string) string {
		for _, c := range *bom.Components {
			if c.Type == cdx.ComponentTypeFile && c.Name == name && c.Properties != nil {
				for _, p := range *c.Properties {
					if p.Name == "dk:origin" {
						return p.Value
					}
				}
			}
		}
		return ""
	}
	owners := func(bom *cdx.BOM, name string) []string {
		var refs []string
		for _, c := range *bom.Components {
			if c.Type == cdx.ComponentTypeFile && c.Name == name {
				for _, d := range *bom.Dependencies {
					if d.Ref == c.BOMRef && d.Dependencies != nil {
						refs = append(refs, *d.Dependencies...)
					}
				}
			}
		}
		return refs
	}

	ginkgo.BeforeEach(func() {
		opts = VerifyOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src", "/build"}}
	})

	ginkgo.DescribeTable("accounts a moved or renamed file under its package", func(moved string) {
		opts.Originals = []Original{original("/usr/share/pkg/data.txt", content)}
		bom := cdx.NewBOM()
		err := Verify(context.Background(), fixtureImage(map[string][]byte{moved: []byte(content)}), bom, opts)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(fileOrigin(bom, moved)).To(gomega.Equal("pm"))
		gomega.Expect(owners(bom, moved)).To(gomega.ContainElement("pm"))
	},
		ginkgo.Entry("moved to another directory", "/opt/moved/data.txt"),
		ginkgo.Entry("renamed in place", "/usr/share/pkg/renamed.txt"),
	)

	ginkgo.It("accounts a copy while the original stays where it was", func() {
		opts.Originals = []Original{original("/usr/share/pkg/data.txt", content)}
		bom := cdx.NewBOM()
		files := map[string][]byte{"/usr/share/pkg/data.txt": []byte(content), "/opt/copy.txt": []byte(content)}
		gomega.Expect(Verify(context.Background(), fixtureImage(files), bom, opts)).To(gomega.Succeed())
		gomega.Expect(fileOrigin(bom, "/opt/copy.txt")).To(gomega.Equal("pm"))
		gomega.Expect(fileOrigin(bom, "/usr/share/pkg/data.txt")).To(gomega.Equal("pm"))
	})

	ginkgo.It("refuses a moved file whose content several originals share", func() {
		opts.Originals = []Original{original("/usr/share/pkg/a.txt", content), original("/usr/share/pkg/b.txt", content)}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/opt/moved/data.txt": []byte(content)}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/opt/moved/data.txt"), gomega.ContainSubstring("ambiguous"))))
	})

	ginkgo.It("refuses a moved file that was also changed", func() {
		opts.Originals = []Original{original("/usr/share/pkg/data.txt", content)}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/opt/moved/data.txt": []byte(content + " edited")}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/opt/moved/data.txt"), gomega.ContainSubstring("no-data"))))
	})

	ginkgo.It("does not match content against files of a commit", func() {
		opts.Originals = []Original{{Path: "/src/data.txt", SHA256: fixtureDigest([]byte(content)), Component: fixtureComponent("git"), Kind: "git"}}
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/opt/moved/data.txt": []byte(content)}), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/opt/moved/data.txt"), gomega.ContainSubstring("no-data"))))
	})

	ginkgo.It("leaves a file under a user root generated, as it was", func() {
		opts.Originals = []Original{original("/usr/share/pkg/data.txt", content)}
		bom := cdx.NewBOM()
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/data.txt": []byte(content)}), bom, opts)).To(gomega.Succeed())
		gomega.Expect(fileOrigin(bom, "/src/data.txt")).To(gomega.Equal("generated"))
	})
})
