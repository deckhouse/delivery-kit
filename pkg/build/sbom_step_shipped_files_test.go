package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/oci/artifact"
)

var _ = Describe("recordShippedFiles", func() {
	var (
		server *httptest.Server
		repo   string
	)

	layerOf := func(files, symlinks map[string]string) v1.Layer {
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

		contents := buf.Bytes()
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(contents)), nil
		})
		Expect(err).To(Succeed())

		return layer
	}

	pushImage := func(ctx SpecContext, files, symlinks map[string]string) string {
		img, err := mutate.AppendLayers(empty.Image, layerOf(files, symlinks))
		Expect(err).To(Succeed())

		digest, err := img.Digest()
		Expect(err).To(Succeed())

		ref, err := name.NewDigest(repo + "@" + digest.String())
		Expect(err).To(Succeed())
		Expect(remote.Write(ref, img, remote.WithContext(ctx))).To(Succeed())

		return digest.String()
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

	BeforeEach(func(ctx SpecContext) {
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())

		server = httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		repo = strings.TrimPrefix(server.URL, "http://") + "/test/stages"
	})

	It("records the files of the image's own packages onto its BOM", func(ctx SpecContext) {
		digest := pushImage(ctx, map[string]string{
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

		recordShippedFiles(ctx, bom, artifact.NewOCIStore(repo, "app"), "app", digest)

		components := *bom.Components
		Expect(lo.FromPtr(components[0].Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/libz.so.1", AdditionalContext: "symlink"},
			{Location: "/usr/lib/libz.so.1.3.1", AdditionalContext: digestOf("zlib body")},
		}))
		Expect(lo.FromPtr(components[1].Evidence.Occurrences)).To(Equal([]cdx.EvidenceOccurrence{
			{Location: "/usr/lib/python3/requests/__init__.py", AdditionalContext: digestOf("requests body")},
		}))
		Expect(components[2].Evidence).To(BeNil())
	})

	It("leaves os-pm packages unmarked when the image was installed by a pm that wrote no file list", func(ctx SpecContext) {
		digest := pushImage(ctx, map[string]string{
			"/var/lib/pm/index.json": `{}`,
			"/usr/lib/libz.so.1.3.1": "zlib body",
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		recordShippedFiles(ctx, bom, artifact.NewOCIStore(repo, "app"), "app", digest)

		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("warns and leaves the BOM as it was when the built image cannot be read", func(ctx SpecContext) {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedFiles(ctx, bom, artifact.NewOCIStore(repo, "app"), "app", "sha256:"+strings.Repeat("0", 64))
		})

		Expect(out).To(ContainSubstring("image app: unable to read the built image sha256:0000"))
		Expect(out).To(ContainSubstring("cached as such until the stage is rebuilt"))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("warns and leaves the BOM as it was when the image's file lists cannot be read", func(ctx SpecContext) {
		digest := pushImage(ctx, map[string]string{
			"/var/lib/pm/index.json": `{}`,
			"/var/lib/pm/files.json": `not json at all`,
		}, nil)

		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "zlib", Name: "zlib", PackageURL: "pkg:generic/zlib@1.3.1"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedFiles(ctx, bom, artifact.NewOCIStore(repo, "app"), "app", digest)
		})

		Expect(out).To(ContainSubstring("image app: unable to read which files the components of the built image " + digest))
		Expect(out).To(ContainSubstring("cached as such until the stage is rebuilt"))
		Expect((*bom.Components)[0].Evidence).To(BeNil())
	})

	It("warns nothing and skips the read when no component could be given files", func(ctx SpecContext) {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			{BOMRef: "yaml", Name: "gopkg.in/yaml.v3", PackageURL: "pkg:golang/gopkg.in/yaml.v3@3.0.1"},
			{BOMRef: "libc6", Name: "libc6", PackageURL: "pkg:deb/debian/libc6@2.36"},
		}}

		out := logged(ctx, func(ctx context.Context) {
			recordShippedFiles(ctx, bom, artifact.NewOCIStore(repo, "app"), "app", "sha256:"+strings.Repeat("0", 64))
		})

		Expect(out).To(BeEmpty())
	})
})
