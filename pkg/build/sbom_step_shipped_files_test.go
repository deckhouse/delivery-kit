package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/werf"
)

type savedImageBackend struct {
	tarball []byte
	err     error
	saved   []string
}

var _ imageSaver = (*savedImageBackend)(nil)

func (b *savedImageBackend) SaveImageToStream(_ context.Context, imageName string) (io.ReadCloser, error) {
	b.saved = append(b.saved, imageName)
	if b.err != nil {
		return nil, b.err
	}

	return io.NopCloser(bytes.NewReader(b.tarball)), nil
}

var _ = Describe("recordShippedScope", func() {
	tarOf := func(files, symlinks map[string]string) []byte {
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, path := range lo.Keys(files) {
			body := files[path]
			Expect(writer.WriteHeader(&tar.Header{
				Name:     strings.TrimPrefix(path, "/"),
				Typeflag: tar.TypeReg,
				Size:     int64(len(body)),
				Mode:     0o644,
			})).To(Succeed())
			_, err := io.WriteString(writer, body)
			Expect(err).To(Succeed())
		}
		for _, path := range lo.Keys(symlinks) {
			Expect(writer.WriteHeader(&tar.Header{
				Name:     strings.TrimPrefix(path, "/"),
				Typeflag: tar.TypeSymlink,
				Linkname: symlinks[path],
				Mode:     0o777,
			})).To(Succeed())
		}
		Expect(writer.Close()).To(Succeed())

		return buf.Bytes()
	}

	// Buildah saves layers uncompressed and Docker may save them either way; tarball.Write
	// copies what Compressed() gives, so the layer type decides which the saved tarball holds.
	gzippedLayer := func(contents []byte) v1.Layer {
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(contents)), nil
		})
		Expect(err).To(Succeed())

		return layer
	}
	uncompressedLayer := func(contents []byte) v1.Layer {
		return static.NewLayer(contents, types.DockerUncompressedLayer)
	}

	backendSaving := func(layerOf func([]byte) v1.Layer, files, symlinks map[string]string) *savedImageBackend {
		img, err := mutate.AppendLayers(empty.Image, layerOf(tarOf(files, symlinks)))
		Expect(err).To(Succeed())

		tag, err := name.NewTag("werf-stages:app")
		Expect(err).To(Succeed())

		var saved bytes.Buffer
		Expect(tarball.Write(tag, img, &saved)).To(Succeed())

		return &savedImageBackend{tarball: saved.Bytes()}
	}

	backendWith := func(files, symlinks map[string]string) *savedImageBackend {
		return backendSaving(gzippedLayer, files, symlinks)
	}

	digestOf := func(body string) string {
		sum := sha256.Sum256([]byte(body))

		return "sha256:" + hex.EncodeToString(sum[:])
	}

	logged := func(ctx SpecContext, record func(ctx context.Context)) string {
		var out bytes.Buffer
		logger := logboek.NewLogger(&out, &out)
		logger.Streams().DisableLineWrapping()
		record(logboek.NewContext(ctx, logger))

		return out.String()
	}

	savedTarballs := func() []string {
		matches, err := filepath.Glob(filepath.Join(werf.GetTmpDir(), "werf-sbom-shipped-files-*.tar"))
		Expect(err).To(Succeed())

		return matches
	}

	BeforeEach(func() {
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
	})

	DescribeTable("records the files of the image's own packages onto its BOM", func(ctx SpecContext, layerOf func([]byte) v1.Layer) {
		backend := backendSaving(layerOf, map[string]string{
			"/var/lib/pm/index.json":                            `{}`,
			"/var/lib/pm/files.json":                            `{"zlib":{"version":"1.3.1","files":{"/usr/lib/libz.so.1.3.1":"sha256:recorded-at-unpack"},"symlinks":{"/usr/lib/libz.so.1":"libz.so.1.3.1"}}}`,
			"/usr/lib/libz.so.1.3.1":                            "zlib body",
			"/usr/lib/python3/requests-2.32.3.dist-info/RECORD": "requests/__init__.py,sha256=x,12\n",
			"/usr/lib/python3/requests/__init__.py":             "requests body",
		}, map[string]string{
			"/usr/lib/libz.so.1": "libz.so.1.3.1",
		})

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1?containerfactoryversion=1"},
			{BOMRef: "requests", Name: "requests", PackageURL: "pkg:pypi/requests@2.32.3"},
			{BOMRef: "libc6", Name: "libc6", PackageURL: "pkg:deb/debian/libc6@2.36"},
		}}

		recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")

		Expect(backend.saved).To(Equal([]string{"werf-stages:app"}))
		components := *bom.Components
		Expect(lo.FromPtr(components[0].Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/libz.so.1", AdditionalContext: "symlink"},
			{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("zlib body")},
		}))
		Expect(lo.FromPtr(components[1].Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("requests body")},
		}))
		Expect(components[2].Evidence).To(BeNil())
		Expect(savedTarballs()).To(BeEmpty())
	},
		Entry("saved with gzipped layers", gzippedLayer),
		Entry("saved with uncompressed layers, as Buildah saves them", uncompressedLayer),
	)

	It("leaves os-pm packages unmarked when the image was installed by a pm that wrote no file list", func(ctx SpecContext) {
		backend := backendWith(map[string]string{
			"/var/lib/pm/index.json": `{}`,
			"/usr/lib/libz.so.1.3.1": "zlib body",
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("a body this image does not hold")},
			}}},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		Expect(out).To(ContainSubstring("/var/lib/pm/files.json is not"))
		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(BeEmpty())
		Expect(lo.FromPtr((*bom.Components)[0].Evidence.Occurrences)).To(HaveLen(1),
			"what the donor recorded is left as it was")
	})

	It("keeps a component whose files this image moved away from the paths its manifest declares", func(ctx SpecContext) {
		backend := backendWith(map[string]string{
			"/usr/lib/python3/moved-1.0.0.dist-info/RECORD": "moved/__init__.py,sha256=x,12\n",
			"/opt/relocated/moved/__init__.py":              "moved body",
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "moved", Name: "moved", PackageURL: "pkg:pypi/moved@1.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/usr/lib/python3/moved/__init__.py", AdditionalContext: digestOf("moved body")},
			}}},
		}}

		recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")

		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(BeEmpty(),
			"the bytes are in the image, so the manifest naming a path they left must not mark the component")
	})

	It("clears a verdict a donor recorded on a component this image does ship", func(ctx SpecContext) {
		backend := backendWith(map[string]string{"/bin/jq": "jq body"}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{
				BOMRef: "jq", Name: "jq", PackageURL: "pkg:generic/jq@1.8.1",
				Properties: &[]cdx.Property{{Name: "werf:shipped", Value: "false"}},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					{Location: "/usr/bin/jq", AdditionalContext: digestOf("jq body")},
				}},
			},
		}}

		recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")

		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(BeEmpty())
	})

	It("marks a component the image's own file lists do not account for and whose files it does not hold", func(ctx SpecContext) {
		backend := backendWith(map[string]string{
			"/usr/lib/python3/kept-1.0.0.dist-info/RECORD": "kept/__init__.py,sha256=x,12\n",
			"/usr/lib/python3/kept/__init__.py":            "kept body",
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "kept", Name: "kept", PackageURL: "pkg:pypi/kept@1.0.0"},
			{BOMRef: "gone", Name: "gone", PackageURL: "pkg:pypi/gone@2.0.0", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/usr/lib/python3/gone/__init__.py", AdditionalContext: digestOf("gone body")},
			}}},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		components := *bom.Components
		Expect(lo.FromPtr(components[0].Properties)).To(BeEmpty(), "the image holds the files this component declares")
		Expect(lo.FromPtr(components[1].Properties)).To(ContainElement(cdx.Property{Name: "werf:shipped", Value: "false"}))
		Expect(out).To(ContainSubstring("image app: 1 components of the SBOM are not shipped by the image"))
	})

	It("keeps a component whose files an import put somewhere else in the image", func(ctx SpecContext) {
		backend := backendWith(map[string]string{"/bin/jq": "jq body"}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "jq", Name: "jq", PackageURL: "pkg:generic/jq@1.8.1", Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/usr/bin/jq", AdditionalContext: digestOf("jq body")},
			}}},
		}}

		recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")

		Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(BeEmpty())
	})

	It("warns and leaves the BOM as it was when the backend cannot save the image", func(ctx SpecContext) {
		backend := &savedImageBackend{err: errors.New("no such image")}
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		Expect(out).To(ContainSubstring("image app: unable to read the built image werf-stages:app"))
		Expect(out).To(ContainSubstring("no such image"))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("warns and leaves the BOM as it was when the saved image is not an image", func(ctx SpecContext) {
		backend := &savedImageBackend{tarball: []byte("not a tarball")}
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		Expect(out).To(ContainSubstring("image app: unable to read the built image werf-stages:app"))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
		Expect(savedTarballs()).To(BeEmpty())
	})

	It("warns and leaves the BOM as it was when the image's file lists cannot be read", func(ctx SpecContext) {
		backend := backendWith(map[string]string{
			"/var/lib/pm/index.json": `{}`,
			"/var/lib/pm/files.json": `not json at all`,
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		Expect(out).To(ContainSubstring("image app: unable to read which files the components of the built image werf-stages:app consist of"))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
		Expect(savedTarballs()).To(BeEmpty())
	})

	It("warns nothing and does not save the image when no component could be given files", func(ctx SpecContext) {
		backend := &savedImageBackend{err: errors.New("must not be called")}
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "yaml", Name: "gopkg.in/yaml.v3", PackageURL: "pkg:golang/gopkg.in/yaml.v3@3.0.1"},
			{BOMRef: "libc6", Name: "libc6", PackageURL: "pkg:deb/debian/libc6@2.36"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedScope(ctx, bom, backend, "app", "werf-stages:app")
		})

		Expect(out).To(BeEmpty())
		Expect(backend.saved).To(BeEmpty())
	})
})
