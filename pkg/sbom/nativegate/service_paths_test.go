package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("werf service paths", func() {
	ginkgo.It("transports exact empty mount evidence without trusting changed destination content", func(ctx ginkgo.SpecContext) {
		paths := []string{"/.werf/tmp/ssh-auth-sock", "/.werf/script.sh"}
		files := map[string][]byte{paths[0]: {}, paths[1]: {}, "/src/base.txt": []byte("base")}
		base := cdx.NewBOM()
		gomega.Expect(Verify(ctx, fixtureImage(files), base, VerifyOptions{Subject: "base", Platform: "linux/amd64", UserRoots: []string{"/src"}, ServiceFiles: paths})).To(gomega.Succeed())
		encoded, err := cyclonedxutil.ToJSON(base)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(cyclonedxutil.ValidateCycloneDX16Schema(encoded)).To(gomega.Succeed())
		var transported cdx.BOM
		gomega.Expect(json.Unmarshal(encoded, &transported)).To(gomega.Succeed())
		originals, err := ImageOriginals(ctx, &transported, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		services, err := ServiceFilesFromBOM(ctx, &transported)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(services).To(gomega.ConsistOf(paths))
		opts := VerifyOptions{Subject: "consumer", Platform: "linux/amd64", Originals: originals, TrustedComponents: *transported.Components, ServiceFiles: services}
		gomega.Expect(Verify(ctx, fixtureImage(files), cdx.NewBOM(), opts)).To(gomega.Succeed())
		files[paths[0]] = []byte("payload")
		gomega.Expect(Verify(ctx, fixtureImage(files), cdx.NewBOM(), opts)).To(gomega.MatchError(gomega.ContainSubstring(paths[0])))
	})
	ginkgo.It("refuses an unrecorded ELF under the reserved directory", func() {
		filename := "/.werf/bin/tool"
		err := Verify(context.Background(), fixtureImage(map[string][]byte{filename: fixtureELF(elf.ET_EXEC, nil)}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(filename), gomega.ContainSubstring("missing"))))
	})
	ginkgo.It("does not exempt nonempty content at an owned mount path", func() {
		filename := "/.werf/tmp/ssh-auth-sock"
		err := Verify(context.Background(), fixtureImage(map[string][]byte{filename: []byte("payload")}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app", ServiceFiles: []string{filename}})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(filename)))
	})
	ginkgo.It("replaces a caller supplied service-file claim with observed evidence", func(ctx ginkgo.SpecContext) {
		bom := cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{Properties: &[]cdx.Property{{Name: "dk:empty-service-file", Value: "/.werf/user"}}}
		gomega.Expect(Verify(ctx, fixtureImage(nil), bom, VerifyOptions{Platform: "linux/amd64", Subject: "app"})).To(gomega.Succeed())
		files, err := ServiceFilesFromBOM(ctx, bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(files).To(gomega.BeEmpty())
	})
	ginkgo.DescribeTable("does not exempt user files under a service directory", func(filename string) {
		for _, body := range [][]byte{[]byte("user payload"), {}, fixtureELF(elf.ET_EXEC, nil)} {
			err := Verify(context.Background(), fixtureImage(map[string][]byte{filename: body}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(filename)))
		}
	},
		ginkgo.Entry("root", "/.werf/payload"),
		ginkgo.Entry("user", "/.werf/user/payload"),
		ginkgo.Entry("scripts", "/.werf/scripts/payload"),
		ginkgo.Entry("stapel", "/.werf/stapel/payload"),
		ginkgo.Entry("archive", "/.werf/archive/payload"),
		ginkgo.Entry("patch", "/.werf/patch/payload"),
		ginkgo.Entry("shell", "/.werf/shell/payload"),
		ginkgo.Entry("observer", "/.werf/js-observer/payload"),
		ginkgo.Entry("context", "/.werf/sbom-build-context/payload"),
		ginkgo.Entry("temporary", "/.werf/tmp/payload"),
	)
	ginkgo.It("requires actual mount provenance even for an empty socket-shaped file", func() {
		filename := "/.werf/tmp/ssh-auth-sock"
		err := Verify(context.Background(), fixtureImage(map[string][]byte{filename: {}}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(filename)))
	})
	ginkgo.DescribeTable("rejects user originals replaced by links under the reserved namespace", func(kind string) {
		img := fixtureImageWithLinks(nil, map[string]string{"/.werf/tmp/file": "missing"})
		original := Original{Path: "/.werf/tmp/file", SHA256: fixtureDigest([]byte("original")), Kind: kind, Component: fixtureComponent(kind)}
		gomega.Expect(Verify(context.Background(), img, cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app", Originals: []Original{original}})).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch")))
		_, err := MaterializeBuildContext(context.Background(), img, &PackageSet{Originals: []Original{original}}, ginkgo.GinkgoT().TempDir(), ContextOptions{Platform: "linux/amd64", Subject: "app", ContainerRoot: "/.werf/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch")))
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
		opts := VerifyOptions{Platform: "linux/amd64", Subject: "app", Originals: []Original{{Path: "/src/file", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}, {Path: "/.werf/tmp/file", SHA256: fixtureDigest([]byte("original")), Kind: "git", Component: fixtureComponent("git")}}}
		gomega.Expect(Verify(context.Background(), img, bom, opts)).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElements(gomega.HaveField("Name", "/src/file"), gomega.HaveField("Name", "/.werf/tmp/file")))
	})

	ginkgo.It("excludes only a proven empty file mountpoint from composition", func() {
		img := fixtureImageWithLinks(map[string][]byte{
			"/.werf/tmp/ssh-auth-sock": {},
			"/src/keep.txt":            []byte("generated"),
		}, nil)
		bom := cdx.NewBOM()
		gomega.Expect(Verify(context.Background(), img, bom, VerifyOptions{Platform: "linux/amd64", Subject: "app", UserRoots: []string{"/src"}, ServiceFiles: []string{"/.werf/tmp/ssh-auth-sock"}})).To(gomega.Succeed())
		gomega.Expect(*bom.Components).To(gomega.ContainElement(gomega.HaveField("Name", "/src/keep.txt")))
		for _, component := range *bom.Components {
			gomega.Expect(component.Name).NotTo(gomega.HavePrefix("/.werf"))
		}
	})

	ginkgo.It("still rejects untrusted files beside the reserved directory", func() {
		err := Verify(context.Background(), fixtureImage(map[string][]byte{"/.werf-other/file": []byte("unknown")}), cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/.werf-other/file")))
	})

	ginkgo.It("maps user files under the reserved directory to package originals normally", func() {
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
		gomega.Expect(declared.Imports).To(gomega.HaveLen(2))
		gomega.Expect(declared.Imports).To(gomega.ContainElements(gomega.HaveField("Path", "/src/sdk.h"), gomega.HaveField("Path", "/.werf/tmp/input")))
	})
})
