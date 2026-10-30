package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const transportELFBody = "\x7fELF not a readable composition"

// A Packet the producer spelled with markup and a line separator: valid JSON string bytes
// that an HTML-escaping encoder would rewrite behind the producer's back.
const transportMarkupNote = "a<b>&c\u2028d"

func transportRegistryHost(ctx context.Context) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://")
}

// Stage files are plain data: an executable bit would make every unbound one a binary the
// gate refuses before it can say anything about original sources.
func transportImage(files map[string]string) v1.Image {
	ginkgo.GinkgoHelper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		gomega.Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0o644, Size: int64(len(files[name]))})).To(gomega.Succeed())
		_, err := writer.Write([]byte(files[name]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	layer, err := fixtureLayer(buffer.Bytes())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return image
}

func transportStage(ctx context.Context, stage string, files map[string]string) (SourceSnapshot, v1.Image) {
	ginkgo.GinkgoHelper()
	image := transportImage(files)
	index, err := shippedscope.IndexImageFiles(ctx, image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(index.Incomplete).To(gomega.BeFalse())

	return SourceSnapshot{Stage: stage, Index: index}, image
}

// The opaque token exceeds float64 precision and the note carries markup and a line
// separator, so neither a generic decoder nor an HTML-escaping encoder could hand the
// Packet back unchanged.
func transportPacket(pkg, pinned, note string) string {
	return fmt.Sprintf(`{"name":%q,"version":"1.0","arch":["linux/amd64"],"digest":%q,"license":"MIT","notes":"`, pkg, pinned) + note + `","opaque":9007199254740993}`
}

func pushTransportOriginal(ctx context.Context, repo, pkg string, files map[string]string) sources.Source {
	ginkgo.GinkgoHelper()

	return pushTransportOriginalNote(ctx, repo, pkg, "plain", files)
}

func pushTransportOriginalNote(ctx context.Context, repo, pkg, note string, files map[string]string) sources.Source {
	ginkgo.GinkgoHelper()
	image := transportImage(files)
	config, err := image.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	config.OS, config.Architecture = "linux", "amd64"
	image, err = mutate.ConfigFile(image, config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	tag, err := name.NewTag(repo + ":" + pkg)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(tag, image, remote.WithContext(ctx))).To(gomega.Succeed())
	pinned, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return sources.Source{Registry: repo, Platform: "linux/amd64", Packet: json.RawMessage(transportPacket(pkg, pinned.String(), note))}
}

func transportReceipt(entries ...sources.Source) *sources.Receipt {
	return &sources.Receipt{Version: sources.Version, Sources: entries}
}

func transportPolicy() *Policy {
	return &Policy{Schema: "dk.policy/v2", Profiles: []string{"c-static", "c-dynamic", "go"}, Images: map[string]ImagePolicy{"app": {Role: "final"}}}
}

func applyTransport(ctx context.Context, snapshots []SourceSnapshot, img v1.Image, base *cdx.BOM) (*cdx.BOM, error) {
	target := cdx.NewBOM()

	return target, ApplySourceSnapshots(ctx, transportPolicy(), "app", img, snapshots, target, ApplySourceSnapshotsOptions{BaseBOM: base})
}

func bomProperty(bom *cdx.BOM, property string) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(bom.Metadata).NotTo(gomega.BeNil())
	gomega.Expect(bom.Metadata.Properties).NotTo(gomega.BeNil())
	for _, candidate := range *bom.Metadata.Properties {
		if candidate.Name == property {
			return candidate.Value
		}
	}
	ginkgo.Fail("no " + property + " property")

	return ""
}

func setBOMProperty(bom *cdx.BOM, property, value string) {
	ginkgo.GinkgoHelper()
	for i, candidate := range *bom.Metadata.Properties {
		if candidate.Name == property {
			(*bom.Metadata.Properties)[i].Value = value

			return
		}
	}
	ginkgo.Fail("no " + property + " property")
}

func transportOriginals(bom *cdx.BOM) originalsCatalog {
	ginkgo.GinkgoHelper()
	var catalog originalsCatalog
	gomega.Expect(json.Unmarshal([]byte(bomProperty(bom, originalsProperty)), &catalog)).To(gomega.Succeed())

	return catalog
}

func transportRecords(bom *cdx.BOM) map[string]Record {
	ginkgo.GinkgoHelper()
	var catalog Catalog
	gomega.Expect(json.Unmarshal([]byte(bomProperty(bom, CatalogProperty)), &catalog)).To(gomega.Succeed())
	records := make(map[string]Record, len(catalog.Records))
	for _, record := range catalog.Records {
		records[record.Path] = record
	}

	return records
}

func setTransportOriginals(bom *cdx.BOM, catalog originalsCatalog) {
	ginkgo.GinkgoHelper()
	data, err := encodeOriginalsCatalog(catalog)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	setBOMProperty(bom, originalsProperty, string(data))
}

func renameBOMProperty(bom *cdx.BOM, property, renamed string) {
	ginkgo.GinkgoHelper()
	for i, candidate := range *bom.Metadata.Properties {
		if candidate.Name == property {
			(*bom.Metadata.Properties)[i].Name = renamed

			return
		}
	}
	ginkgo.Fail("no " + property + " property")
}

func baseWithOriginals(catalog originalsCatalog) *cdx.BOM {
	ginkgo.GinkgoHelper()
	data, err := encodeOriginalsCatalog(catalog)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Properties: &[]cdx.Property{{Name: originalsProperty, Value: string(data)}}}

	return bom
}

// Published SBOMs travel as JSON, so the inherited catalog is read back the way a
// consumer gets it rather than from the producer's own objects.
func serializedBOM(bom *cdx.BOM) *cdx.BOM {
	ginkgo.GinkgoHelper()
	data, err := cyclonedxutil.ToJSON(bom)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return restored
}

func onlyTransportSource(catalog originalsCatalog) string {
	ginkgo.GinkgoHelper()
	ids := slices.Sorted(maps.Keys(catalog.Sources))
	gomega.Expect(ids).To(gomega.HaveLen(1))

	return ids[0]
}

func boundaryStages(ctx context.Context, inventory bool) ([]SourceSnapshot, sources.Source, string) {
	ginkgo.GinkgoHelper()
	repo := transportRegistryHost(ctx) + "/test/original"
	source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/file": "tool body"})
	files := map[string]string{"/usr/file": "tool body"}
	if inventory {
		files[pmIndexPath] = "{}"
		files[sources.DefaultPath] = transportReceiptFile(transportReceipt(source))
	}
	from, _ := transportStage(ctx, "from", map[string]string{})
	installed, _ := transportStage(ctx, "packages", files)
	installed.Receipt = transportReceipt(source)

	return []SourceSnapshot{from, installed}, source, repo
}

func transportReceiptFile(receipt *sources.Receipt) string {
	ginkgo.GinkgoHelper()
	encoded, err := sources.Encode(receipt)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return string(encoded)
}

// installedBuild is the shape the following specs inherit from: one original installed at
// the package stage and moved by the shell into /src.
func installedBuild(ctx context.Context) (*cdx.BOM, v1.Image, sources.Source) {
	ginkgo.GinkgoHelper()
	repo := transportRegistryHost(ctx) + "/test/original"
	source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/file": "tool body", "/usr/hidden": "hidden body", "/usr/other": "other body"})

	from, _ := transportStage(ctx, "from", map[string]string{})
	packages, _ := transportStage(ctx, "packages", map[string]string{"/usr/file": "tool body", "/usr/hidden": "hidden body"})
	packages.Receipt = transportReceipt(source)
	install, image := transportStage(ctx, "install", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})

	bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return bom, image, source
}

var _ = ginkgo.Describe("Original source transport", func() {
	ginkgo.It("carries an installed original through a shell rename without reconstructing it", func(ctx ginkgo.SpecContext) {
		bom, _, source := installedBuild(ctx)

		catalog := transportOriginals(bom)
		id := onlyTransportSource(catalog)
		gomega.Expect(string(catalog.Sources[id].Packet)).To(gomega.Equal(string(source.Packet)))
		gomega.Expect(string(catalog.Sources[id].Packet)).To(gomega.ContainSubstring("9007199254740993"))
		gomega.Expect(catalog.Sources[id].Registry).To(gomega.Equal(source.Registry))
		gomega.Expect(slices.Sorted(maps.Keys(catalog.Files))).To(gomega.Equal([]string{"/src/hidden", "/src/tool"}))
		gomega.Expect(catalog.Files["/src/tool"]).To(gomega.Equal(originalFileRecord{
			SHA256:   digest([]byte("tool body")),
			Size:     int64(len("tool body")),
			Bindings: []originalBinding{{Source: id, Path: "usr/file"}},
		}))
		gomega.Expect(catalog.Files["/src/hidden"].Bindings).To(gomega.Equal([]originalBinding{{Source: id, Path: "usr/hidden"}}))

		records := transportRecords(bom)
		gomega.Expect(slices.Sorted(maps.Keys(records))).To(gomega.Equal([]string{"/src/hidden", "/src/tool"}))
		gomega.Expect(records["/src/tool"].Origin).To(gomega.Equal("pm"))
		gomega.Expect(records["/src/tool"].Owners).To(gomega.Equal([]string{id}))
		gomega.Expect(records["/src/tool"].SHA256).To(gomega.Equal(digest([]byte("tool body"))))
	})

	ginkgo.It("refuses snapshots that do not end at the verified image", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/file": "tool body"})
		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, _ := transportStage(ctx, "packages", map[string]string{"/usr/file": "tool body"})
		packages.Receipt = transportReceipt(source)
		_, other := transportStage(ctx, "install", map[string]string{"/usr/file": "tool body", "/usr/extra": "extra"})

		_, err := applyTransport(ctx, []SourceSnapshot{from, packages}, other, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: final source snapshot differs from the verified image")))
	})

	ginkgo.It("re-reads the inherited originals from a published base SBOM", func(ctx ginkgo.SpecContext) {
		first, image, _ := installedBuild(ctx)
		base := serializedBOM(first)

		from, _ := transportStage(ctx, "from", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})
		second, err := applyTransport(ctx, []SourceSnapshot{from}, image, base)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(transportOriginals(second)).To(gomega.Equal(transportOriginals(first)))
		gomega.Expect(transportRecords(second)).To(gomega.Equal(transportRecords(first)))
	})

	ginkgo.It("refuses a file of the base its descendant replaced on the same path", func(ctx ginkgo.SpecContext) {
		first, _, _ := installedBuild(ctx)
		base := serializedBOM(first)

		from, _ := transportStage(ctx, "from", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})
		install, image := transportStage(ctx, "install", map[string]string{"/src/tool": "own body", "/src/hidden": "hidden body"})
		_, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, base)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("hash-mismatch: /src/tool no longer holds the content its original source bound there")))
	})

	ginkgo.DescribeTable("refuses an inherited catalog neither the snapshot nor the original backs", func(ctx ginkgo.SpecContext, damage func(catalog *originalsCatalog, id string), expected string) {
		first, image, _ := installedBuild(ctx)
		base := serializedBOM(first)
		catalog := transportOriginals(base)
		damage(&catalog, onlyTransportSource(catalog))
		setTransportOriginals(base, catalog)

		from, _ := transportStage(ctx, "from", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})
		_, err := applyTransport(ctx, []SourceSnapshot{from}, image, base)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("a recorded digest the snapshot does not hold", func(catalog *originalsCatalog, _ string) {
			record := catalog.Files["/src/tool"]
			record.SHA256 = digest([]byte("other body"))
			catalog.Files["/src/tool"] = record
		}, "invalid: originals catalog does not match source snapshot at /src/tool"),
		ginkgo.Entry("a binding to an unknown source", func(catalog *originalsCatalog, id string) {
			delete(catalog.Sources, id)
		}, "no-data: missing source"),
		ginkgo.Entry("a binding to other bytes of the original", func(catalog *originalsCatalog, id string) {
			record := catalog.Files["/src/tool"]
			record.Bindings = []originalBinding{{Source: id, Path: "usr/other"}}
			catalog.Files["/src/tool"] = record
		}, "invalid: original bytes mismatch at /src/tool"),
		ginkgo.Entry("a binding to a path the original does not hold", func(catalog *originalsCatalog, id string) {
			record := catalog.Files["/src/tool"]
			record.Bindings = []originalBinding{{Source: id, Path: "usr/absent"}}
			catalog.Files["/src/tool"] = record
		}, "usr/absent"),
		ginkgo.Entry("a file record carrying no binding", func(catalog *originalsCatalog, _ string) {
			record := catalog.Files["/src/tool"]
			record.Bindings = nil
			catalog.Files["/src/tool"] = record
		}, "invalid: originals catalog does not match source snapshot at /src/tool"),
	)

	ginkgo.DescribeTable("refuses a base SBOM whose originals catalog cannot be read", func(ctx ginkgo.SpecContext, damage func(bom *cdx.BOM), expected string) {
		first, image, _ := installedBuild(ctx)
		base := serializedBOM(first)
		damage(base)

		from, _ := transportStage(ctx, "from", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})
		_, err := applyTransport(ctx, []SourceSnapshot{from}, image, base)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	},
		ginkgo.Entry("truncated JSON", func(bom *cdx.BOM) {
			setBOMProperty(bom, originalsProperty, `{"schema":"dk:originals/v1","sources":{}`)
		}, "invalid originals catalog"),
		ginkgo.Entry("an unexpected field", func(bom *cdx.BOM) {
			setBOMProperty(bom, originalsProperty, `{"schema":"dk:originals/v1","sources":{},"files":{},"extra":1}`)
		}, "invalid originals catalog"),
		ginkgo.Entry("another catalog schema", func(bom *cdx.BOM) {
			setBOMProperty(bom, originalsProperty, `{"schema":"dk:originals/v2","sources":{},"files":{}}`)
		}, "no-data: incomplete or unsupported originals catalog"),
		ginkgo.Entry("no files map at all", func(bom *cdx.BOM) {
			setBOMProperty(bom, originalsProperty, `{"schema":"dk:originals/v1","sources":{}}`)
		}, "no-data: incomplete or unsupported originals catalog"),
		ginkgo.Entry("two catalogs in one SBOM", func(bom *cdx.BOM) {
			*bom.Metadata.Properties = append(*bom.Metadata.Properties, cdx.Property{Name: originalsProperty, Value: bomProperty(bom, originalsProperty)})
		}, "invalid: duplicate originals catalog"),
		ginkgo.Entry("a catalog property of a version this gate does not know", func(bom *cdx.BOM) {
			renameBOMProperty(bom, originalsProperty, "dk:originals/v2")
		}, "unsupported inherited originals catalog property dk:originals/v2"),
		ginkgo.Entry("a newer catalog property beside the known one", func(bom *cdx.BOM) {
			*bom.Metadata.Properties = append(*bom.Metadata.Properties, cdx.Property{Name: "dk:originals/v2", Value: "{}"})
		}, "unsupported inherited originals catalog property dk:originals/v2"),
	)

	ginkgo.It("does not swallow an inherited source the registry no longer holds", func(ctx ginkgo.SpecContext) {
		first, image, source := installedBuild(ctx)
		base := serializedBOM(first)
		catalog := transportOriginals(base)
		id := onlyTransportSource(catalog)

		dangling, err := transportImage(map[string]string{"/usr/file": "never pushed"}).Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gone := "pm-source:" + digest([]byte("gone"))
		catalog.Sources[gone] = sources.Source{Registry: source.Registry, Platform: "linux/amd64", Packet: json.RawMessage(transportPacket("tool", dangling.String(), "plain"))}
		// /src/hidden keeps its verified binding and sorts first, so a swallowed failure
		// at /src/tool would still produce a catalog.
		record := catalog.Files["/src/tool"]
		record.Bindings = []originalBinding{{Source: gone, Path: "usr/file"}}
		catalog.Files["/src/tool"] = record
		gomega.Expect(catalog.Files["/src/hidden"].Bindings).To(gomega.Equal([]originalBinding{{Source: id, Path: "usr/hidden"}}))
		setTransportOriginals(base, catalog)

		from, _ := transportStage(ctx, "from", map[string]string{"/src/tool": "tool body", "/src/hidden": "hidden body"})
		_, err = applyTransport(ctx, []SourceSnapshot{from}, image, base)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: original " + source.Registry + "@" + dangling.String())))
	})

	ginkgo.It("ignores a legacy pm file inventory the snapshots do not need", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/file": "tool body"})
		legacy := map[string]string{
			"/usr/file":                             "tool body",
			"/var/lib/pm/index.json":                `{"tool": not json at all`,
			"/var/lib/pm/files.json":                `{"tool": not json at all`,
			"/var/lib/pm/container-factory-version": "",
		}

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", legacy)
		packages.Receipt = transportReceipt(source)

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(transportRecords(bom)))).To(gomega.Equal([]string{"/usr/file"}))
	})

	ginkgo.It("refuses a pm index that comes with no source receipt", func(ctx ginkgo.SpecContext) {
		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/var/lib/pm/index.json": "{}"})

		_, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: pm index has no original source receipt at packages")))
	})

	ginkgo.It("accepts a receipt that explicitly opened no source", func(ctx ginkgo.SpecContext) {
		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/var/lib/pm/index.json": "{}"})
		packages.Receipt = transportReceipt()

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportOriginals(bom).Files).To(gomega.BeEmpty())
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty())
	})

	ginkgo.It("keeps both origins of a file two originals ship identically", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		first := pushTransportOriginal(ctx, repo, "first", map[string]string{"/etc/shared.txt": "shared body", "/usr/extra": "first"})
		second := pushTransportOriginal(ctx, repo, "second", map[string]string{"/etc/shared.txt": "shared body", "/usr/extra": "second"})

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/etc/shared.txt": "shared body"})
		packages.Receipt = transportReceipt(first, second)

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		catalog := transportOriginals(bom)
		gomega.Expect(catalog.Sources).To(gomega.HaveLen(2))
		gomega.Expect(catalog.Files["/etc/shared.txt"].Bindings).To(gomega.HaveLen(2))
		for _, binding := range catalog.Files["/etc/shared.txt"].Bindings {
			gomega.Expect(binding.Path).To(gomega.Equal("etc/shared.txt"))
			gomega.Expect(catalog.Sources).To(gomega.HaveKey(binding.Source))
		}
		gomega.Expect(transportRecords(bom)).To(gomega.BeEmpty())
	})

	ginkgo.It("refuses an ambiguous binary before reading what it embeds", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		first := pushTransportOriginal(ctx, repo, "first", map[string]string{"/usr/app": transportELFBody, "/usr/extra": "first"})
		second := pushTransportOriginal(ctx, repo, "second", map[string]string{"/usr/app": transportELFBody, "/usr/extra": "second"})

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/usr/app": transportELFBody})
		packages.Receipt = transportReceipt(first, second)

		_, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/usr/app: no-data: 2 original bindings, need exactly one")))
	})

	ginkgo.It("keeps the evidence a retained path already had while a moved copy gains both", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/one": "same body", "/usr/two": "same body"})

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, _ := transportStage(ctx, "packages", map[string]string{"/usr/one": "same body", "/usr/two": "same body"})
		packages.Receipt = transportReceipt(source)
		install, image := transportStage(ctx, "install", map[string]string{"/usr/one": "same body", "/opt/two": "same body"})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		catalog := transportOriginals(bom)
		id := onlyTransportSource(catalog)
		gomega.Expect(catalog.Files["/usr/one"].Bindings).To(gomega.Equal([]originalBinding{{Source: id, Path: "usr/one"}}))
		gomega.Expect(catalog.Files["/opt/two"].Bindings).To(gomega.Equal([]originalBinding{{Source: id, Path: "usr/one"}, {Source: id, Path: "usr/two"}}))
		records := transportRecords(bom)
		gomega.Expect(records["/usr/one"].Owners).To(gomega.Equal([]string{id}))
		gomega.Expect(records["/opt/two"].Owners).To(gomega.Equal([]string{id}))
	})

	ginkgo.It("does not let a dependency stage hand evidence to a new equal-byte path", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginal(ctx, repo, "tool", map[string]string{"/usr/one": "same body"})

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, _ := transportStage(ctx, "packages", map[string]string{"/usr/one": "same body"})
		packages.Receipt = transportReceipt(source)
		dependencies, image := transportStage(ctx, "dependencies", map[string]string{"/usr/one": "same body", "/opt/copy": "same body"})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages, dependencies}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(transportOriginals(bom).Files))).To(gomega.Equal([]string{"/usr/one"}))
		gomega.Expect(transportRecords(bom)).NotTo(gomega.HaveKey("/opt/copy"))
	})

	ginkgo.It("does not borrow a unique equal-byte owner for a file with distinct source alternatives", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		first := pushTransportOriginal(ctx, repo, "first", map[string]string{"/usr/shared": "same", "/usr/anchor": "same"})
		second := pushTransportOriginal(ctx, repo, "second", map[string]string{"/usr/shared": "same"})
		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/usr/shared": "same", "/usr/anchor": "same"})
		packages.Receipt = transportReceipt(first, second)
		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportOriginals(bom).Files["/usr/shared"].Bindings).To(gomega.HaveLen(2))
		gomega.Expect(transportRecords(bom)).To(gomega.HaveKey("/usr/anchor"))
		gomega.Expect(transportRecords(bom)).NotTo(gomega.HaveKey("/usr/shared"))
	})

	ginkgo.It("refuses to serialize a binding with no resolved source", func(ctx ginkgo.SpecContext) {
		snapshot, _ := transportStage(ctx, "from", map[string]string{"/data": "data"})
		evidence := &sourceEvidence{index: snapshot.Index, resolved: map[string]*resolvedSource{}, matches: originalMatches{"/data": {{Source: "missing", Path: "data"}}}}
		gomega.Expect(evidence.attach(cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("no-data")))
	})

	ginkgo.It("binds only what an import actually copies", func(ctx ginkgo.SpecContext) {
		artifact, artifactImage, _ := installedBuild(ctx)
		artifactIndex, err := shippedscope.IndexImageFiles(ctx, artifactImage)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		from, _ := transportStage(ctx, "from", map[string]string{})
		install, image := transportStage(ctx, "install", map[string]string{"/dest/tool": "tool body", "/dest/hidden": "hidden body"})
		install.Imports = []SourceImport{{
			Index: artifactIndex,
			BOM:   serializedBOM(artifact),
			Scope: ImportScope{FromPath: "/src", ToPath: "/dest", IncludePaths: []string{"tool"}},
		}}

		bom, err := applyTransport(ctx, []SourceSnapshot{from, install}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		catalog := transportOriginals(bom)
		gomega.Expect(slices.Sorted(maps.Keys(catalog.Files))).To(gomega.Equal([]string{"/dest/tool"}))
		gomega.Expect(catalog.Files["/dest/tool"].Bindings).To(gomega.Equal([]originalBinding{{Source: onlyTransportSource(catalog), Path: "usr/file"}}))
		gomega.Expect(slices.Sorted(maps.Keys(transportRecords(bom)))).To(gomega.Equal([]string{"/dest/tool"}))
	})

	ginkgo.It("hands back a Packet the producer spelled with markup and a line separator", func(ctx ginkgo.SpecContext) {
		repo := transportRegistryHost(ctx) + "/test/original"
		source := pushTransportOriginalNote(ctx, repo, "tool", transportMarkupNote, map[string]string{"/usr/file": "tool body"})

		from, _ := transportStage(ctx, "from", map[string]string{})
		packages, image := transportStage(ctx, "packages", map[string]string{"/usr/file": "tool body"})
		packages.Receipt = transportReceipt(source)

		first, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bomProperty(first, originalsProperty)).To(gomega.ContainSubstring(transportMarkupNote))
		catalog := transportOriginals(first)
		gomega.Expect(string(catalog.Sources[onlyTransportSource(catalog)].Packet)).To(gomega.Equal(string(source.Packet)))

		again, _ := transportStage(ctx, "from", map[string]string{"/usr/file": "tool body"})
		again.Receipt = transportReceipt(source)
		second, err := applyTransport(ctx, []SourceSnapshot{again}, image, serializedBOM(first))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportOriginals(second)).To(gomega.Equal(catalog))
	})

	ginkgo.It("refuses a pm inventory a shell stage brings in", func(ctx ginkgo.SpecContext) {
		stages, _, _ := boundaryStages(ctx, false)
		install, image := transportStage(ctx, "install", map[string]string{"/usr/file": "tool body", pmIndexPath: "{}"})

		_, err := applyTransport(ctx, append(stages, install), image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: install changes pm install metadata outside a package stage: " + pmIndexPath)))
	})

	ginkgo.It("refuses an inventory and receipt a shell stage installs for itself", func(ctx ginkgo.SpecContext) {
		stages, _, repo := boundaryStages(ctx, false)
		other := pushTransportOriginal(ctx, repo, "other", map[string]string{"/usr/file": "tool body", "/usr/extra": "other"})
		receipt := transportReceipt(other)
		install, image := transportStage(ctx, "install", map[string]string{"/usr/file": "tool body", pmIndexPath: "{}", sources.DefaultPath: transportReceiptFile(receipt)})
		install.Receipt = receipt

		_, err := applyTransport(ctx, append(stages, install), image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: install changes pm install metadata outside a package stage")))
	})

	ginkgo.It("refuses a receipt a shell stage opens without any lock file", func(ctx ginkgo.SpecContext) {
		stages, _, repo := boundaryStages(ctx, false)
		other := pushTransportOriginal(ctx, repo, "other", map[string]string{"/usr/file": "tool body", "/usr/extra": "other"})
		install, image := transportStage(ctx, "install", map[string]string{"/usr/file": "tool body"})
		install.Receipt = transportReceipt(other)

		_, err := applyTransport(ctx, append(stages, install), image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: install opens package sources outside a package stage")))
	})

	ginkgo.It("refuses pm metadata a dependency stage changes with no declared import", func(ctx ginkgo.SpecContext) {
		stages, _, _ := boundaryStages(ctx, false)
		dependencies, image := transportStage(ctx, "dependencies", map[string]string{"/usr/file": "tool body", pmIndexPath: "{}"})

		_, err := applyTransport(ctx, append(stages, dependencies), image, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: dependencies changes pm install metadata outside a package stage")))
	})

	ginkgo.It("accepts the unchanged receipt a shell stage carries while it cleans the inventory up", func(ctx ginkgo.SpecContext) {
		stages, source, _ := boundaryStages(ctx, true)
		install, image := transportStage(ctx, "install", map[string]string{"/usr/file": "tool body"})
		install.Receipt = transportReceipt(source)

		bom, err := applyTransport(ctx, append(stages, install), image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(transportOriginals(bom).Files))).To(gomega.Equal([]string{"/usr/file"}))
	})

	ginkgo.It("accepts pm metadata a dependency stage copies in with a declared import", func(ctx ginkgo.SpecContext) {
		artifact, artifactImage, _ := installedBuild(ctx)
		artifactIndex, err := shippedscope.IndexImageFiles(ctx, artifactImage)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		from, _ := transportStage(ctx, "from", map[string]string{})
		dependencies, image := transportStage(ctx, "dependencies", map[string]string{"/dest/tool": "tool body", pmIndexPath: "{}"})
		dependencies.Imports = []SourceImport{{
			Index: artifactIndex,
			BOM:   serializedBOM(artifact),
			Scope: ImportScope{FromPath: "/src/tool", ToPath: "/dest/tool"},
		}}

		bom, err := applyTransport(ctx, []SourceSnapshot{from, dependencies}, image, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(transportOriginals(bom).Files))).To(gomega.Equal([]string{"/dest/tool"}))
	})

	ginkgo.It("keeps both origins when an import lands bytes a prior binding already explains", func(ctx ginkgo.SpecContext) {
		artifact, _, first := installedBuild(ctx)
		firstID := onlyTransportSource(transportOriginals(artifact))

		second := pushTransportOriginal(ctx, strings.TrimSuffix(first.Registry, "original")+"second", "copy", map[string]string{"/opt/copy": "tool body", "/opt/extra": "second"})
		fromSecond, _ := transportStage(ctx, "from", map[string]string{})
		packagesSecond, secondImage := transportStage(ctx, "packages", map[string]string{"/opt/copy": "tool body"})
		packagesSecond.Receipt = transportReceipt(second)
		secondBOM, err := applyTransport(ctx, []SourceSnapshot{fromSecond, packagesSecond}, secondImage, nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		secondIndex, err := shippedscope.IndexImageFiles(ctx, secondImage)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		base := baseWithOriginals(originalsCatalog{
			Schema:  originalsProperty,
			Sources: map[string]sources.Source{firstID: first},
			Files: map[string]originalFileRecord{"/dest/file": {
				SHA256:   digest([]byte("tool body")),
				Size:     int64(len("tool body")),
				Bindings: []originalBinding{{Source: firstID, Path: "usr/file"}},
			}},
		})
		from, _ := transportStage(ctx, "from", map[string]string{"/dest/file": "tool body"})
		dependencies, image := transportStage(ctx, "dependencies", map[string]string{"/dest/file": "tool body"})
		dependencies.Imports = []SourceImport{{
			Index: secondIndex,
			BOM:   serializedBOM(secondBOM),
			Scope: ImportScope{FromPath: "/opt/copy", ToPath: "/dest/file"},
		}}

		bom, err := applyTransport(ctx, []SourceSnapshot{from, dependencies}, image, base)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bindings := transportOriginals(bom).Files["/dest/file"].Bindings
		gomega.Expect(bindings).To(gomega.HaveLen(2))
		gomega.Expect(bindings[0].Source).NotTo(gomega.Equal(bindings[1].Source))
		gomega.Expect(bindings).To(gomega.ContainElement(originalBinding{Source: firstID, Path: "usr/file"}))
		gomega.Expect(transportRecords(bom)).NotTo(gomega.HaveKey("/dest/file"))
	})

	// The evidence chain answers the same way the producer context does: what a
	// packages stage unpacks is identified by the package it came out of, so a file it
	// installs takes no binding from resembling one the image already holds.
	ginkgo.It("gives a file a packages stage installed no binding from equal bytes", func(ctx ginkgo.SpecContext) {
		// The source identity is the one a build of it published, so the inherited
		// catalog is built from a real one rather than from a name made up here.
		artifact, _, source := installedBuild(ctx)
		id := onlyTransportSource(transportOriginals(artifact))
		base := baseWithOriginals(originalsCatalog{
			Schema:  originalsProperty,
			Sources: map[string]sources.Source{id: source},
			Files: map[string]originalFileRecord{"/dest/one": {
				SHA256:   digest([]byte("tool body")),
				Size:     int64(len("tool body")),
				Bindings: []originalBinding{{Source: id, Path: "usr/file"}},
			}},
		})

		from, _ := transportStage(ctx, "from", map[string]string{"/dest/one": "tool body"})
		packages, image := transportStage(ctx, "packages", map[string]string{
			"/dest/one": "tool body",
			"/go/pkg/mod/example.com/thing@v1/fixture": "tool body",
		})

		bom, err := applyTransport(ctx, []SourceSnapshot{from, packages}, image, base)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		catalog := transportOriginals(bom)
		gomega.Expect(catalog.Files).To(gomega.HaveKey("/dest/one"), "the path that held the evidence keeps it")
		gomega.Expect(catalog.Files).NotTo(gomega.HaveKey("/go/pkg/mod/example.com/thing@v1/fixture"),
			"what the packages stage unpacked is not evidence of a declared source")
	})

	ginkgo.It("merges a repeated import binding into the one the path already holds", func(ctx ginkgo.SpecContext) {
		artifact, artifactImage, first := installedBuild(ctx)
		firstID := onlyTransportSource(transportOriginals(artifact))
		artifactIndex, err := shippedscope.IndexImageFiles(ctx, artifactImage)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		base := baseWithOriginals(originalsCatalog{
			Schema:  originalsProperty,
			Sources: map[string]sources.Source{firstID: first},
			Files: map[string]originalFileRecord{"/dest/tool": {
				SHA256:   digest([]byte("tool body")),
				Size:     int64(len("tool body")),
				Bindings: []originalBinding{{Source: firstID, Path: "usr/file"}},
			}},
		})
		from, _ := transportStage(ctx, "from", map[string]string{"/dest/tool": "tool body"})
		dependencies, image := transportStage(ctx, "dependencies", map[string]string{"/dest/tool": "tool body"})
		dependencies.Imports = []SourceImport{{
			Index: artifactIndex,
			BOM:   serializedBOM(artifact),
			Scope: ImportScope{FromPath: "/src/tool", ToPath: "/dest/tool"},
		}}

		bom, err := applyTransport(ctx, []SourceSnapshot{from, dependencies}, image, base)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(transportOriginals(bom).Files["/dest/tool"].Bindings).To(gomega.Equal([]originalBinding{{Source: firstID, Path: "usr/file"}}))
		gomega.Expect(transportRecords(bom)).To(gomega.HaveKey("/dest/tool"))
	})
})
