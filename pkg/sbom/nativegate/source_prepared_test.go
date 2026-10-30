package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// preparedTree is what a prepared source image collects: the files of a source
// distribution, taken out of the toolchain image that opened them.
func preparedTree() map[string]string {
	return map[string]string{
		"/usr/local/go/src/runtime/defs.h":  bootstrapHeader,
		"/usr/local/go/src/runtime/proc.go": "package runtime\n",
	}
}

func preparedImported(files map[string]string) map[string]string {
	imported := make(map[string]string, len(files))
	for name, body := range files {
		imported[strings.Replace(name, "/usr/local/go/src", "/src", 1)] = body
	}

	return imported
}

// preparedSourceLabels declare the package the image says it is. The digest is not among
// them: that is the image's own, and a label claiming another is a forgery.
func preparedSourceLabels(pkg string) map[string]string {
	return map[string]string{
		"pkg.name": pkg, "pkg.version": "1.0", "pkg.type": "source", "pkg.arch": "linux/amd64",
		"unrelated": "ignored",
	}
}

func preparedSourceImage(files, labels map[string]string) v1.Image {
	ginkgo.GinkgoHelper()
	image := transportImage(files)
	config, err := image.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	config.OS, config.Architecture = "linux", "amd64"
	config.Config.Labels = labels
	image, err = mutate.ConfigFile(image, config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return image
}

// registryDigestOf answers what the image is pinned by in the registry. The verification
// reads an image saved out of the daemon and re-assembled, whose own digest is this
// process's making, so the two are deliberately kept apart.
func registryDigestOf(image v1.Image) string {
	ginkgo.GinkgoHelper()
	digest, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return digest.String()
}

// verifyPreparedSource runs the verification of a prepared source image: one built from
// scratch whose single stage imports a tree out of a bootstrap source.
func verifyPreparedSource(ctx context.Context, sourceFiles map[string]string, image v1.Image, preparedSource bool) (*cdx.BOM, error) {
	ginkgo.GinkgoHelper()

	return verifyPreparedSourceAt(ctx, sourceFiles, image, preparedSource, registryDigestOf(image))
}

func verifyPreparedSourceAt(ctx context.Context, sourceFiles map[string]string, image v1.Image, preparedSource bool, registryDigest string) (*cdx.BOM, error) {
	ginkgo.GinkgoHelper()
	index, err := shippedscope.IndexImageFiles(ctx, image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(index.Incomplete).To(gomega.BeFalse())

	from, _ := transportStage(ctx, "from", map[string]string{})
	install := SourceSnapshot{Stage: "install", Index: index, Imports: []SourceImport{{
		Index:     bootstrapIndex(ctx, sourceFiles),
		Bootstrap: true,
		Scope:     ImportScope{FromPath: "/usr/local/go/src", ToPath: "/src"},
	}}}

	target := cdx.NewBOM()

	return target, ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
		[]SourceSnapshot{from, install}, target,
		ApplySourceSnapshotsOptions{PreparedSource: preparedSource, RegistryDigest: registryDigest})
}

// pushPreparedSource publishes a verified prepared source image as the package it says it
// is, so that a build downstream can pin it the way it pins any other prepared source.
func pushPreparedSource(ctx context.Context, repo, pkg string, image v1.Image) sources.Source {
	ginkgo.GinkgoHelper()
	tag, err := name.NewTag(repo + ":" + pkg)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(tag, image, remote.WithContext(ctx))).To(gomega.Succeed())
	pinned, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return sources.Source{Registry: repo, Platform: "linux/amd64", Packet: json.RawMessage(transportPacket(pkg, pinned.String(), "plain"))}
}

// onlyBOMComponent reads back the one component of the document carrying this identity.
func onlyBOMComponent(bom *cdx.BOM, ref string) cdx.Component {
	ginkgo.GinkgoHelper()
	gomega.Expect(bom.Components).NotTo(gomega.BeNil())
	for _, component := range *bom.Components {
		if component.BOMRef == ref {
			return component
		}
	}
	ginkgo.Fail("no component " + ref + " in the document")

	return cdx.Component{}
}

var _ = ginkgo.Describe("A prepared source image", func() {
	ginkgo.It("describes the files it collected as the package it declares itself to be", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))

		bom, err := verifyPreparedSource(ctx, files, image, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		records := transportRecords(bom)
		gomega.Expect(slices.Sorted(maps.Keys(records))).To(gomega.Equal([]string{"/src/runtime/defs.h", "/src/runtime/proc.go"}))
		id := "urn:dk:prepared-source:" + strings.TrimPrefix(registryDigestOf(image), "sha256:")
		for _, record := range records {
			gomega.Expect(record.Origin).To(gomega.Equal("pm"))
			gomega.Expect(record.Owners).To(gomega.Equal([]string{id}))
			gomega.Expect(record.Components).To(gomega.Equal([]string{id}))
		}

		component := onlyBOMComponent(bom, id)
		gomega.Expect(component.Name).To(gomega.Equal("go-source"))
		gomega.Expect(component.Version).To(gomega.Equal("1.0"))
		gomega.Expect(component.PackageURL).To(gomega.Equal("pkg:generic/go-source@1.0"))
	})

	// The image the verification reads was saved out of the daemon and re-assembled
	// here, so its own digest is this process's making: what a build downstream pins is
	// what the registry holds, and that is what the package has to be named by.
	ginkgo.It("is pinned by the digest it has in the registry, not by the one of the image at hand", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		registry := "sha256:" + strings.Repeat("ab", 32)
		image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))
		gomega.Expect(registry).NotTo(gomega.Equal(registryDigestOf(image)))

		bom, err := verifyPreparedSourceAt(ctx, files, image, true, registry)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		id := "urn:dk:prepared-source:" + strings.TrimPrefix(registry, "sha256:")
		gomega.Expect(onlyBOMComponent(bom, id).BOMRef).To(gomega.Equal(id))
		for _, record := range transportRecords(bom) {
			gomega.Expect(record.Owners).To(gomega.Equal([]string{id}))
		}
	})

	// The package labels may state the digest, and then it is the registry's that they
	// have to agree with.
	ginkgo.It("accepts a declared digest that is the one the registry holds", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		registry := "sha256:" + strings.Repeat("cd", 32)
		labels := preparedSourceLabels("go-source")
		labels["pkg.digest"] = registry

		_, err := verifyPreparedSourceAt(ctx, files, preparedSourceImage(preparedImported(files), labels), true, registry)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.It("refuses a declared digest the registry contradicts", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		labels := preparedSourceLabels("go-source")
		labels["pkg.digest"] = "sha256:" + strings.Repeat("ef", 32)
		image := preparedSourceImage(preparedImported(files), labels)

		_, err := verifyPreparedSourceAt(ctx, files, image, true, "sha256:"+strings.Repeat("cd", 32))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("contradicts image digest")))
	})

	ginkgo.It("pins nothing where the registry digest is unknown", func(ctx ginkgo.SpecContext) {
		files := preparedTree()

		_, err := verifyPreparedSourceAt(ctx, files, preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source")), true, "")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: the digest the image has in the registry is unknown")))
	})

	// An image importing from this one keeps of its document what it says occurs at a
	// path the copy carries, and drops what states no whereabouts at all.
	ginkgo.It("states where in itself the files of that package stand", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))

		bom, err := verifyPreparedSource(ctx, files, image, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		component := onlyBOMComponent(bom, "urn:dk:prepared-source:"+strings.TrimPrefix(registryDigestOf(image), "sha256:"))
		gomega.Expect(component.Evidence).NotTo(gomega.BeNil())
		occurrences := *component.Evidence.Occurrences
		gomega.Expect(occurrences).To(gomega.HaveLen(2))
		gomega.Expect(occurrences[0].Location).To(gomega.Equal("/src/runtime/defs.h"))
		gomega.Expect(occurrences[0].AdditionalContext).To(gomega.HavePrefix("sha256:"))
		gomega.Expect(component.Properties).NotTo(gomega.BeNil())
		for _, property := range *component.Properties {
			gomega.Expect(property.Name).NotTo(gomega.Equal("werf:pm:containerFactoryVersion"))
		}
	})

	// It takes files out of a bootstrap source without answering for them one by one,
	// and it hands that permission to nobody: it publishes no obligation at all.
	ginkgo.It("publishes no bootstrap marks", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		bom, err := verifyPreparedSource(ctx, files, preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source")), true)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bootstrapPublishedMarks(bom)).To(gomega.BeEmpty())
	})

	// The permission is the prepared source's alone: the very same import into an image
	// that is not one leaves every file to be answered for.
	ginkgo.It("is the only image that may take those files without answering for them", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		_, err := verifyPreparedSource(ctx, files, preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source")), false)

		gomega.Expect(err).To(gomega.MatchError(gomega.MatchRegexp(
			`no-data: /src/runtime/\S+ comes from a bootstrap source with neither a build record nor an original binding`)))
	})

	// The exemption is for what it takes out of a bootstrap image itself. An obligation
	// another image already published over those paths is that image's statement, and
	// collecting the files is not what answers it.
	ginkgo.It("keeps an obligation it inherited from an import of a strict image", func(ctx ginkgo.SpecContext) {
		collected := preparedImported(preparedTree())
		marked := cdx.NewBOM()
		marks, err := bootstrapMarksProperty(map[string]bool{"/opt/marked.h": true})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		marked.Metadata = &cdx.Metadata{Properties: &[]cdx.Property{marks}}

		donor := map[string]string{"/opt/marked.h": "#define MARKED 1\n"}
		collected["/src/marked.h"] = donor["/opt/marked.h"]
		image := preparedSourceImage(collected, preparedSourceLabels("go-source"))
		index, err := shippedscope.IndexImageFiles(ctx, image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		from, _ := transportStage(ctx, "from", map[string]string{})
		install := SourceSnapshot{Stage: "install", Index: index, Imports: []SourceImport{
			{
				Index:     bootstrapIndex(ctx, preparedTree()),
				Bootstrap: true,
				Scope:     ImportScope{FromPath: "/usr/local/go/src", ToPath: "/src"},
			},
			{
				Index: bootstrapIndex(ctx, donor),
				BOM:   marked,
				Scope: ImportScope{FromPath: "/opt/marked.h", ToPath: "/src/marked.h"},
			},
		}}

		err = ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image, []SourceSnapshot{from, install},
			cdx.NewBOM(), ApplySourceSnapshotsOptions{PreparedSource: true, RegistryDigest: registryDigestOf(image)})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /src/marked.h comes from a bootstrap source with neither a build record nor an original binding")))
	})

	ginkgo.It("reads no package out of an image that declares none", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		_, err := verifyPreparedSource(ctx, files, preparedSourceImage(preparedImported(files), map[string]string{"pkg.name": "go-source"}), true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("prepared source image: packet JSON from image labels")))
	})

	// What a compiled artifact is made of lives in the record of the build that made it,
	// and the name of the file says nothing about whether it is one.
	ginkgo.DescribeTable("refuses compiled content, whatever the file is called",
		func(ctx ginkgo.SpecContext, body string) {
			files := preparedTree()
			files["/usr/local/go/src/runtime/notes.txt"] = body
			image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))

			_, err := verifyPreparedSource(ctx, files, image, true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
				"invalid: /src/runtime/notes.txt is compiled content, which a prepared source image does not ship")))
		},
		ginkgo.Entry("an ELF executable", string(minimalRuntimeELF(elf.ET_EXEC))),
		ginkgo.Entry("an ELF object", string(minimalRuntimeELF(elf.ET_REL))),
		ginkgo.Entry("a static library", "!<arch>\n/               0           0     0     0       4         `\n"),
		ginkgo.Entry("a thin archive", "!<thin>\n/               0           0     0     0       4         `\n"),
		ginkgo.Entry("a PE image", "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"),
		ginkgo.Entry("a COFF object", "\x64\x86\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		ginkgo.Entry("a Mach-O object", "\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x01\x00\x00\x00"),
		ginkgo.Entry("a fat Mach-O binary", "\xca\xfe\xba\xbe\x00\x00\x00\x02\x01\x00\x00\x07\x00\x00\x00\x03"),
		ginkgo.Entry("a WebAssembly module", "\x00asm\x01\x00\x00\x00"),
		ginkgo.Entry("an LLVM bitcode module", "BC\xc0\xde\x35\x14\x00\x00\x05\x00\x00\x00\x62\x0c\x30\x24"),
		ginkgo.Entry("a wrapped LLVM bitcode module", "\xde\xc0\x17\x0b\x00\x00\x00\x00\x14\x00\x00\x00\x88\x0d\x00\x00"),
	)

	// The rule reads bytes, so a source file keeps being one however it is named. (A
	// name the older binaryLike guard recognizes - .a, .o, .so - is refused by that
	// guard instead, for having no record, which is not this rule.)
	ginkgo.It("ships a source file that merely bears the name of a library", func(ctx ginkgo.SpecContext) {
		files := preparedTree()
		files["/usr/local/go/src/runtime/runtime.lib"] = "package runtime\n"
		image := preparedSourceImage(preparedImported(files), preparedSourceLabels("go-source"))

		bom, err := verifyPreparedSource(ctx, files, image, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportRecords(bom)).To(gomega.HaveKey("/src/runtime/runtime.lib"))
	})
})

var _ = ginkgo.Describe("An image importing straight out of a prepared source image", func() {
	// Such an import is not how a prepared source is meant to be consumed - a build
	// pins the package and reads the files out of it - and the gate treats it as the
	// ordinary import it is: the document of the donor carries no original binding for
	// those files, so they arrive unbound and are read as the plain text they are.
	ginkgo.It("receives the files unbound, as any other import of plain text", func(ctx ginkgo.SpecContext) {
		collected := preparedTree()
		prepared := preparedSourceImage(preparedImported(collected), preparedSourceLabels("go-source"))
		published, err := verifyPreparedSource(ctx, collected, prepared, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		landed := map[string]string{"/opt/src/runtime/defs.h": bootstrapHeader}
		from, _ := transportStage(ctx, "from", map[string]string{})
		install, image := transportStage(ctx, "install", landed)
		install.Imports = []SourceImport{{
			Index: bootstrapIndex(ctx, preparedImported(collected)),
			BOM:   published,
			Scope: ImportScope{FromPath: "/src/runtime/defs.h", ToPath: "/opt/src/runtime/defs.h"},
		}}

		target := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from, install}, target, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())
		gomega.Expect(transportRecords(target)).To(gomega.BeEmpty(), "nothing binds them here; the package of the donor is not read as one")
		gomega.Expect(bootstrapPublishedMarks(target)).To(gomega.BeEmpty())
	})
})

var _ = ginkgo.Describe("A build that stands on a prepared source image", func() {
	// The toolchain image compiles what the prepared source ships; an image importing
	// its files maps them to that package, and the package is the image itself.
	chain := func(ctx context.Context, later map[string]string) error {
		ginkgo.GinkgoHelper()
		collected := preparedTree()
		prepared := preparedSourceImage(preparedImported(collected), preparedSourceLabels("go"))
		_, err := verifyPreparedSource(ctx, collected, prepared, true)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		packet := pushPreparedSource(ctx, transportRegistryHost(ctx)+"/test/prepared", "go", prepared)

		toolchain := map[string]string{
			"/usr/local/go/pkg/tool/compile":   string(minimalRuntimeELF(elf.ET_EXEC)),
			"/usr/local/go/src/runtime/defs.h": bootstrapHeader,
		}
		from, _ := transportStage(ctx, "from", map[string]string{})
		install, image := transportStage(ctx, "install", bootstrapImported(toolchain))
		install.Imports = []SourceImport{{
			Index:     bootstrapIndex(ctx, toolchain),
			Bootstrap: true,
			Packages:  []sources.Source{packet},
			Originals: []ImportOriginal{{Root: "/usr/local/go/src", OriginalPath: "src", PackageName: "go", PackageVersion: "1.0"}},
			Scope:     ImportScope{FromPath: "/usr/local/go", ToPath: "/opt/go"},
		}}
		snapshots := []SourceSnapshot{from, install}
		if later != nil {
			var setup SourceSnapshot
			setup, image = transportStage(ctx, "setup", later)
			snapshots = append(snapshots, setup)
		}

		return ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image, snapshots, cdx.NewBOM(), ApplySourceSnapshotsOptions{})
	}

	ginkgo.It("binds the files of the toolchain to the package that prepared source is", func(ctx ginkgo.SpecContext) {
		gomega.Expect(chain(ctx, nil)).To(gomega.Succeed())
	})

	ginkgo.It("refuses a bound file this build then edited", func(ctx ginkgo.SpecContext) {
		edited := bootstrapImported(map[string]string{
			"/usr/local/go/pkg/tool/compile":   string(minimalRuntimeELF(elf.ET_EXEC)),
			"/usr/local/go/src/runtime/defs.h": "#define RUNTIME 2\n",
		})

		gomega.Expect(chain(ctx, edited)).To(gomega.MatchError(gomega.ContainSubstring(
			"hash-mismatch: /opt/go/src/runtime/defs.h comes from a bootstrap source and no longer holds the bytes of the original it was bound to")))
	})
})
