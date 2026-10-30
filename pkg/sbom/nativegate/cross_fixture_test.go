package nativegate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// The four cross-built CLI artifacts of the pinned producer capture, with the
// hashes of its manifest and of the records the record reader extracted.
var crossCLITargets = []struct {
	name, path, bodySHA256, recordSHA256, artifact, profile, platform string
}{
	{"go-darwin-amd64", "/download/go-darwin-amd64",
		"sha256:afe276bc8515aecd23db43566d8cd611790cebfe42d2a5b797345544446c8335",
		"sha256:ee2417d1fb19f1a7533394183228581a272482e7cbc9e8b2751a5d8bacaee368",
		"macho", "go-macho", "darwin/amd64"},
	{"go-darwin-arm64", "/download/go-darwin-arm64",
		"sha256:46435400faca319060974e9037ea06b85c8c92fb8e980806aecfd02f357c2d42",
		"sha256:f5e5bda2e340b9b406cfe59afe15795fff91184aaa6fd70bb59c9c6eecaff565",
		"macho", "go-macho", "darwin/arm64"},
	{"go-windows-amd64.exe", "/download/go-windows-amd64.exe",
		"sha256:7ef28a2b2ed55e33052283d8c2480b3ec7aa7212ac97696143bc8ede73c35247",
		"sha256:dc90f9346dd07c840bf175792d7088768d84cc90e6d2ec572d4b45d44737da09",
		"pe", "go-pe", "windows/amd64"},
	{"go-linux-arm", "/download/go-linux-arm",
		"sha256:8846d60614cc49d8d15675c12df9e7ab9c13b68d00a88c5294289772fd7b7e5c",
		"sha256:25d2b37f532f780f60c54591cf8f040b49081496db5369db82b30a4f54b087ee",
		"elf", "go", "linux/arm"},
}

func crossCLIFixtureRoot() string {
	ginkgo.GinkgoHelper()
	root := os.Getenv("DK_CROSS_CLI_FIXTURE")
	if root == "" {
		ginkgo.Skip("requires pinned DK_CROSS_CLI_FIXTURE (mandatory in task test:native-poc)")
	}
	return root
}

func crossCLIBody(name, bodySHA256 string) []byte {
	ginkgo.GinkgoHelper()
	body, err := os.ReadFile(filepath.Join(crossCLIFixtureRoot(), name))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(body)).To(gomega.Equal(bodySHA256))
	return body
}

func crossCLIRecord(name, recordSHA256 string) []byte {
	ginkgo.GinkgoHelper()
	expected, err := os.ReadFile(filepath.Join(crossCLIFixtureRoot(), name+".sbom.json"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(expected)).To(gomega.Equal(recordSHA256))
	return expected
}

func crossCLIImageFiles() map[string]string {
	ginkgo.GinkgoHelper()
	files := map[string]string{}
	for _, target := range crossCLITargets {
		files[target.path] = string(crossCLIBody(target.name, target.bodySHA256))
	}
	return files
}

// crossCLICatalog asserts the shipped default policy inventories every
// cross-built artifact and returns the catalog it attached to the BOM.
func crossCLICatalog(bom *cdx.BOM) Catalog {
	ginkgo.GinkgoHelper()
	catalog, err := ReadCatalog([]*cdx.BOM{bom})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(catalog.Records).To(gomega.HaveLen(len(crossCLITargets)))
	byPath := map[string]Record{}
	for _, record := range catalog.Records {
		byPath[record.Path] = record
	}
	for _, target := range crossCLITargets {
		record, known := byPath[target.path]
		gomega.Expect(known).To(gomega.BeTrue(), target.path)
		gomega.Expect(record.SHA256).To(gomega.Equal(target.bodySHA256))
		gomega.Expect(record.Profile).To(gomega.Equal(target.profile))
		gomega.Expect(record.Composition).To(gomega.MatchJSON(crossCLIRecord(target.name, target.recordSHA256)))
		gomega.Expect(record.Tools).To(gomega.HaveLen(4))
		gomega.Expect(record.Components).To(gomega.HaveLen(2))
		var composition shared.BuildRecord
		gomega.Expect(json.Unmarshal(record.Composition, &composition)).To(gomega.Succeed())
		gomega.Expect(composition.Artifact).To(gomega.Equal(target.artifact))
		gomega.Expect(composition.Profile.Platform).To(gomega.Equal(target.platform))
	}
	return catalog
}

func crossCLIMutation(name, bodySHA256 string, mutate func([]byte)) v1.Image {
	ginkgo.GinkgoHelper()
	body := crossCLIBody(name, bodySHA256)
	mutate(body)
	return fixtureImage(map[string]string{"/download/" + name: string(body)})
}

// overwrite replaces every occurrence of marker with the same number of bytes.
func overwrite(body []byte, marker, replacement string) {
	ginkgo.GinkgoHelper()
	gomega.Expect(replacement).To(gomega.HaveLen(len(marker)))
	gomega.Expect(bytes.Contains(body, []byte(marker))).To(gomega.BeTrue(), marker)
	for offset := 0; ; {
		found := bytes.Index(body[offset:], []byte(marker))
		if found < 0 {
			return
		}
		offset += found
		copy(body[offset:], replacement)
		offset += len(marker)
	}
}

// bareCOFFObject builds the smallest AMD64 COFF object the record reader
// classifies: a complete header and one section header, with no DOS stub.
func bareCOFFObject() []byte {
	object := make([]byte, 60)
	binary.LittleEndian.PutUint16(object[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(object[2:], 1)
	return object
}

var _ = ginkgo.Describe("Cross-built CLI producer fixtures", func() {
	ginkgo.It("inventories every foreign native artifact shipped as an ordinary payload file", func(ctx ginkgo.SpecContext) {
		bom := cdx.NewBOM()
		img := fixtureImage(crossCLIImageFiles())
		gomega.Expect(Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", img, nil, bom)).To(gomega.Succeed())
		libraries := map[string]string{}
		sources := map[string]string{}
		for _, component := range *bom.Components {
			if component.Type != cdx.ComponentTypeLibrary {
				continue
			}
			libraries[component.Name] = component.Version
			var source shared.BuildSource
			gomega.Expect(component.Properties).NotTo(gomega.BeNil())
			gomega.Expect(json.Unmarshal([]byte((*component.Properties)[0].Value), &source)).To(gomega.Succeed())
			sources[component.Name] = source.Kind
		}
		gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "golang": "1.27.3"}))
		// The packet distribution the Go toolchain came from stays separate
		// from the declared source of the executable it built.
		gomega.Expect(sources).To(gomega.Equal(map[string]string{"sbom.test/app": "declared", "golang": "pm"}))
		catalog := crossCLICatalog(bom)
		gomega.Expect(catalog.Components).To(gomega.HaveLen(2))
	})

	ginkgo.It("verifies the same artifacts against observed original sources", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(crossCLIImageFiles())
		before, err := shippedscope.IndexImageFiles(ctx, empty.Image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		after, err := shippedscope.IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		snapshots := []SourceSnapshot{{Stage: "from", Index: before}, {Stage: "install", Index: after}}
		bom := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, NewDefaultPolicy(ctx, "app"), "app", img, snapshots, bom, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())
		crossCLICatalog(bom)
	})

	ginkgo.It("never resolves foreign runtime references through the Linux rootfs", func(ctx ginkgo.SpecContext) {
		foreign := []string{}
		machOFile, err := macho.NewFile(bytes.NewReader(crossCLIBody(crossCLITargets[0].name, crossCLITargets[0].bodySHA256)))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		dylibs, err := machOFile.ImportedLibraries()
		gomega.Expect(machOFile.Close()).To(gomega.Succeed())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(dylibs).NotTo(gomega.BeEmpty())
		foreign = append(foreign, dylibs...)
		peFile, err := pe.NewFile(bytes.NewReader(crossCLIBody(crossCLITargets[2].name, crossCLITargets[2].bodySHA256)))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		optional, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(peFile.Close()).To(gomega.Succeed())
		gomega.Expect(optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress).NotTo(gomega.BeZero())

		files := crossCLIImageFiles()
		files["/app"] = string(minimalRuntimeELF(elf.ET_EXEC))
		bom := cdx.NewBOM()
		gomega.Expect(Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", fixtureImage(files), nil, bom)).To(gomega.Succeed())
		dependencies := map[string][]string{}
		for _, dependency := range *bom.Dependencies {
			gomega.Expect(dependency.Dependencies).NotTo(gomega.BeNil())
			dependencies[dependency.Ref] = *dependency.Dependencies
		}
		for _, target := range crossCLITargets {
			refs := dependencies[target.bodySHA256+":"+target.path]
			gomega.Expect(refs).To(gomega.HaveLen(2), target.path)
			for _, ref := range refs {
				gomega.Expect(ref).To(gomega.HavePrefix("urn:dk:component:"), target.path)
			}
		}
		for _, component := range *bom.Components {
			for _, name := range foreign {
				gomega.Expect(component.Name).NotTo(gomega.Equal(name))
				gomega.Expect(component.Name).NotTo(gomega.Equal(filepath.Base(name)))
			}
		}
		// The reader reports foreign import names as diagnostics; nothing of
		// them reaches the BOM, neither as a component nor as a property.
		windows := crossCLIBody(crossCLITargets[2].name, crossCLITargets[2].bodySHA256)
		gomega.Expect(bytes.Contains(windows, []byte("kernel32.dll"))).To(gomega.BeTrue())
		encoded, err := json.Marshal(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, name := range append(foreign, "kernel32.dll") {
			gomega.Expect(string(encoded)).NotTo(gomega.ContainSubstring(name))
		}
	})

	ginkgo.DescribeTable("gates a cross-built artifact on the exact recorded profile ID",
		func(ctx ginkgo.SpecContext, profile string, index int, expected string) {
			policy := NewDefaultPolicy(ctx, "app")
			policy.Profiles = []string{profile}
			target := crossCLITargets[index]
			img := fixtureImage(map[string]string{target.path: string(crossCLIBody(target.name, target.bodySHA256))})
			err := Apply(ctx, policy, "app", img, nil, cdx.NewBOM())
			if expected == "" {
				gomega.Expect(err).To(gomega.Succeed())
				return
			}
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
		},
		ginkgo.Entry("go-macho permits the Mach-O target", "go-macho", 0, ""),
		ginkgo.Entry("go-macho rejects the PE target", "go-macho", 2, "unsupported: build profile go-pe"),
		ginkgo.Entry("go alone rejects the Mach-O target", "go", 0, "unsupported: build profile go-macho"),
		ginkgo.Entry("go alone rejects the PE target", "go", 2, "unsupported: build profile go-pe"),
		ginkgo.Entry("go permits the Linux ARM target", "go", 3, ""),
	)

	ginkgo.It("reads a bare COFF object in full instead of sampling its prefix as ordinary content", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string]string{"/var/lib/pm/blob": string(bareCOFFObject())})
		err := Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", img, nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/var/lib/pm/blob: unsupported: COFF objects are unsupported")))
	})

	ginkgo.DescribeTable("refuses a native magic the reader does not select instead of reading it as ordinary content",
		func(ctx ginkgo.SpecContext, body, expected string) {
			err := Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", fixtureImage(map[string]string{"/download/tool": body}), nil, cdx.NewBOM())
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
		},
		ginkgo.Entry("a 64-bit universal Mach-O header", "\xca\xfe\xba\xbf"+strings.Repeat("\x01", 60), "/download/tool: invalid: malformed fat Mach-O"),
		ginkgo.Entry("a byte-swapped 64-bit universal Mach-O header", "\xbf\xba\xfe\xca"+strings.Repeat("\x01", 60), "/download/tool: invalid: malformed fat Mach-O"),
		ginkgo.Entry("printable text behind a DOS stub marker", "MZ this is not an image\n", "/download/tool: unsupported: not a selected native executable or shared object"),
	)

	ginkgo.DescribeTable("refuses a mutated cross-built artifact instead of treating it as ordinary content",
		func(ctx ginkgo.SpecContext, index int, mutate func([]byte), expected string) {
			target := crossCLITargets[index]
			img := crossCLIMutation(target.name, target.bodySHA256, mutate)
			err := Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", img, nil, cdx.NewBOM())
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
			gomega.Expect(err).NotTo(gomega.MatchError(gomega.ContainSubstring("unknown binary or unsupported format")))
			gomega.Expect(err).NotTo(gomega.MatchError(gomega.ContainSubstring("has no embedded composition reader")))
		},
		ginkgo.Entry("an uninstrumented Mach-O", 0, func(body []byte) {
			overwrite(body, "__pkgnote", "__zzznote")
		}, "no-data: missing sbom metadata"),
		ginkgo.Entry("an uninstrumented PE", 2, func(body []byte) {
			overwrite(body, ".pkgnote", ".zzznote")
		}, "no-data: missing sbom metadata"),
		ginkgo.Entry("a cleared Mach-O carrier payload", 0, func(body []byte) {
			overwrite(body, `{"sbom":{`, "\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		}, "invalid: invalid __pkgnote alignment padding"),
		ginkgo.Entry("a Go setting contradicting the recorded platform", 1, func(body []byte) {
			overwrite(body, "GOOS=darwin", "GOOS=darwiX")
		}, `invalid: Go setting GOOS=darwiX contradicts target profile darwin/arm64`),
		ginkgo.Entry("a record claiming another architecture", 0, func(body []byte) {
			overwrite(body, `"platform":"darwin/amd64"`, `"platform":"darwin/arm64"`)
		}, `invalid: profile platform "darwin/arm64" does not match darwin/amd64`),
		ginkgo.Entry("a Mach-O shared library", 0, func(body []byte) {
			binary.LittleEndian.PutUint32(body[12:], uint32(macho.TypeDylib))
		}, "unsupported: unsupported Mach-O type"),
		ginkgo.Entry("a PE dynamic link library", 2, func(body []byte) {
			offset := int64(binary.LittleEndian.Uint32(body[0x3c:])) + 4 + 18
			binary.LittleEndian.PutUint16(body[offset:], binary.LittleEndian.Uint16(body[offset:])|pe.IMAGE_FILE_DLL)
		}, "unsupported: not a standalone PE executable image"),
		ginkgo.Entry("a Mach-O magic claiming a universal binary", 0, func(body []byte) {
			binary.BigEndian.PutUint32(body[0:], 0xcafebabe)
		}, "invalid: malformed fat Mach-O"),
	)
})
