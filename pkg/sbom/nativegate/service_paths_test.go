package nativegate

import (
	"context"
	"debug/elf"
	"os"
	"path/filepath"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("werf service paths", func() {
	ginkgo.DescribeTable("ignores service originals replaced by links", func(kind string) {
		img := fixtureImageWithLinks(nil, map[string]string{"/.werf/tmp/file": "missing"})
		original := Original{Path: "/.werf/tmp/file", SHA256: fixtureDigest([]byte("original")), Kind: kind, Component: fixtureComponent(kind)}
		gomega.Expect(Verify(context.Background(), img, cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app", Originals: []Original{original}})).To(gomega.Succeed())
		_, err := MaterializeBuildContext(context.Background(), img, &PackageSet{Originals: []Original{original}}, ginkgo.GinkgoT().TempDir(), ContextOptions{Platform: "linux/amd64", Subject: "app", ContainerRoot: "/.werf/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}, ginkgo.Entry("git", "git"), ginkgo.Entry("pm", "pm"), ginkgo.Entry("bootstrap", "bootstrap"))

	ginkgo.It("rejects hiding an outside original inside the reserved namespace", func() {
		img := fixtureImageWithLinks(map[string][]byte{"/.werf/input.c": []byte("changed")}, map[string]string{"/public": "/.werf"})
		opts := VerifyOptions{Platform: "linux/amd64", Subject: "app", Originals: []Original{{Path: "/public/input.c", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}}
		err := Verify(context.Background(), img, cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/public/input.c"), gomega.ContainSubstring("reserved service"))))
	})

	ginkgo.It("rejects a changed outside original resolved through service symlinks", func() {
		img := fixtureImageWithLinks(map[string][]byte{"/src/input.c": []byte("changed")}, map[string]string{
			"/public": "/.werf/alias", "/.werf/alias": "/src",
		})
		opts := VerifyOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src"}, Originals: []Original{{Path: "/public/input.c", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}}
		err := Verify(context.Background(), img, cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/src/input.c"), gomega.ContainSubstring("hash-mismatch"))))
	})

	ginkgo.It("verifies outside hardlinks backed by service files", func() {
		img := fixtureImageWithLinkTypes(map[string][]byte{"/.werf/tmp/file": []byte("original")}, nil, map[string]string{"/src/file": "/.werf/tmp/file"})
		bom := cdx.NewBOM()
		opts := VerifyOptions{Platform: "linux/amd64", Subject: "app", Originals: []Original{{Path: "/src/file", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}}
		gomega.Expect(Verify(context.Background(), img, bom, opts)).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.HaveField("Name", "/src/file")))
		for _, component := range *bom.Components {
			gomega.Expect(component.Name).NotTo(gomega.HavePrefix("/.werf"))
		}
	})

	ginkgo.It("excludes service files and links from verification and composition", func() {
		img := fixtureImageWithLinks(map[string][]byte{
			"/.werf/tmp/ssh-auth-sock": {},
			"/.werf/bin/tool":          fixtureELF(elf.ET_EXEC, nil),
			"/src/keep.txt":            []byte("generated"),
		}, map[string]string{"/.werf/tmp/link": "missing"})
		bom := cdx.NewBOM()
		gomega.Expect(Verify(context.Background(), img, bom, VerifyOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src"}, ExpectedSymlinks: map[string]string{"/.werf/tmp/link": "old"}})).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.HaveField("Name", "/src/keep.txt")))
		for _, component := range *bom.Components {
			gomega.Expect(component.Name).NotTo(gomega.HavePrefix("/.werf"))
		}
	})

	ginkgo.It("still rejects untrusted files beside the reserved directory", func() {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/.werf-other/file": []byte("unknown")}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/.werf-other/file")))
	})

	ginkgo.It("does not map service files to package originals in the helper context", func() {
		set := fixturePackageSet("/usr/include/sdk.h")
		directory := ginkgo.GinkgoT().TempDir()
		_, err := MaterializeBuildContext(context.Background(), fixtureImage(map[string][]byte{
			"/.werf/tmp/input": []byte("original"),
			"/src/sdk.h":       []byte("original"),
		}), set, directory, ContextOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src"}, ContainerRoot: "/.werf/context"})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		body, err := os.ReadFile(filepath.Join(directory, "context.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		declared, err := buildcontext.Decode(body)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declared.Imports).To(gomega.HaveLen(1))
		gomega.Expect(declared.Imports[0].Path).To(gomega.Equal("/src/sdk.h"))
	})
})
