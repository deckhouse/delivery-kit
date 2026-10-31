package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"go.uber.org/mock/gomock"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

// recordingPatcher records the document a patcher is handed, so a test can tell what the
// patchers of a build get to see and how often they run.
type recordingPatcher struct {
	runs      int
	purls     []string
	bomRefs   []string
	lastCount int
}

func (p *recordingPatcher) Apply(_ context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	p.runs++
	p.purls = nil
	p.bomRefs = nil
	for _, comp := range lo.FromPtr(bom.Components) {
		p.purls = append(p.purls, comp.PackageURL)
		p.bomRefs = append(p.bomRefs, comp.BOMRef)
	}
	p.lastCount = len(lo.FromPtr(bom.Components))

	return bom, nil
}

var _ = Describe("Common SBOM pipeline", func() {
	const stageDigest = "pipeline"

	var (
		server   *httptest.Server
		repo     string
		ctrl     *gomock.Controller
		backend  *mock.MockContainerBackend
		step     *sbomStep
		scanOpts scanner.ScanOptions
		saves    int
	)

	// pipelineImage pushes an image holding the given files and carrying the record of the
	// single base stage its whole filesystem was built as, which is what the convergence
	// reads the composition of the image from.
	pipelineImage := func(ctx context.Context, files map[string][]byte, directories ...string) *imagePkg.StageDesc {
		GinkgoHelper()
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, directory := range directories {
			Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(directory, "/") + "/", Typeflag: tar.TypeDir, Mode: 0o755})).To(Succeed())
		}
		for _, path := range lo.Keys(files) {
			Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(path, "/"), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[path]))})).To(Succeed())
			_, err := writer.Write(files[path])
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(writer.Close()).To(Succeed())
		layer, err := fixtureLayer(buf.Bytes())
		Expect(err).NotTo(HaveOccurred())
		img, err := mutate.AppendLayers(empty.Image, layer)
		Expect(err).NotTo(HaveOccurred())
		cfg, err := img.ConfigFile()
		Expect(err).NotTo(HaveOccurred())
		cfg.Config.Labels = map[string]string{imagePkg.WerfSBOMStageLabel: `{"stage":"from","stageDigest":"` + stageDigest + `","parentStageID":""}`}
		img, err = mutate.ConfigFile(img, cfg)
		Expect(err).NotTo(HaveOccurred())

		ref, err := name.NewTag(repo + ":app")
		Expect(err).NotTo(HaveOccurred())
		Expect(remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		digest, err := img.Digest()
		Expect(err).NotTo(HaveOccurred())

		var saved bytes.Buffer
		Expect(tarball.Write(ref, img, &saved)).To(Succeed())
		info := &imagePkg.Info{Name: ref.Name(), Repository: repo, RepoDigest: repo + "@" + digest.String()}
		backend.EXPECT().Pull(gomock.Any(), info.Name, gomock.Any()).Return(nil).AnyTimes()
		backend.EXPECT().SaveImageToStream(gomock.Any(), info.Name).
			DoAndReturn(func(_ any, _ string) (io.ReadCloser, error) {
				saves++

				return io.NopCloser(bytes.NewReader(saved.Bytes())), nil
			}).AnyTimes()

		return &imagePkg.StageDesc{StageID: imagePkg.NewStageID(stageDigest, 1), Info: info}
	}

	BeforeEach(func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server = httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		repo = strings.TrimPrefix(server.URL, "http://") + "/common"
		ctrl = gomock.NewController(GinkgoT())
		backend = mock.NewMockContainerBackend(ctrl)
		step = &sbomStep{containerBackend: backend}
		saves = 0
		scanOpts = scanner.DefaultSyftScanOptions()
		// No packages directive: nothing is scanned, the composition is verified and the
		// inherited documents are merged.
		scanOpts.Commands[0].Catalogers = nil
	})

	// The catalog of a published document is only worth the refs it names: a reader takes
	// a record, reads the components it says the file was made of, and looks each of them
	// up among the document's components. The shape here is the acceptance capture's - a
	// record over a built file, naming catalog keys - and the question asked of it is the
	// one that capture answers wrongly: does every ref resolve.
	Describe("the catalog of the published document", func() {
		publishedOf := func(ctx context.Context, base *cdx.BOM, files map[string][]byte) (*cdx.BOM, nativegate.Catalog, map[string]bool) {
			GinkgoHelper()
			desc := pipelineImage(ctx, files)
			Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, nil, nil, true, "", nil, "")).To(Succeed())
			bom, err := step.GetImageBOM(ctx, "app", desc.Info)
			Expect(err).NotTo(HaveOccurred())

			property, found := catalogPropertyOf(bom)
			Expect(found).To(BeTrue(), "the published document carries a catalog")
			var catalog nativegate.Catalog
			Expect(json.Unmarshal([]byte(property.Value), &catalog)).To(Succeed())

			declared := map[string]bool{}
			eachComponent(bom, func(comp cdx.Component) {
				if comp.BOMRef != "" {
					declared[comp.BOMRef] = true
				}
			})

			return bom, catalog, declared
		}

		It("names components the published document declares", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			_, catalog, declared := publishedOf(ctx, nil, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

			Expect(catalog.Records).NotTo(BeEmpty())
			named := 0
			for _, record := range catalog.Records {
				for _, ref := range append(append([]string{}, record.Components...), record.Owners...) {
					named++
					Expect(declared).To(HaveKey(ref), "record "+record.Path+" names a component the document does not declare")
					Expect(catalog.Components).To(HaveKey(ref), "record "+record.Path+" names a component the catalog does not hold")
				}
			}
			Expect(named).NotTo(BeZero(), "a catalog that names nothing proves nothing")
		})

		// The check a consumer makes, made here: a document whose catalog does not load
		// through the reader DK itself uses to read an inherited catalog is a document
		// nobody can resolve.
		It("loads through the reader a consumer of it uses", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			bom, _, _ := publishedOf(ctx, nil, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

			catalog, err := nativegate.ReadCatalog([]*cdx.BOM{bom})

			Expect(err).NotTo(HaveOccurred())
			Expect(catalog.Records).NotTo(BeEmpty())
			for ref, component := range catalog.Components {
				Expect(component.BOMRef).To(Equal(ref))
			}
		})

		It("names them by the refs the document gives rather than the ones the verification used", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			_, catalog, _ := publishedOf(ctx, nil, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

			for ref := range catalog.Components {
				Expect(ref).NotTo(HavePrefix("urn:dk:component:"),
					"the verification's own ref does not survive publication and must not be published")
			}
		})

		// The merge renames refs to keep two documents apart. A base that survives the
		// drop of superseded attribution is merged in here, so the proven component is
		// renamed with a document's worth of others around it.
		It("resolves when a base document is merged in", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			base := cyclonedxutil.NewBOM()
			base.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "base", BOMRef: "base"}}
			base.Components = &[]cdx.Component{
				{Type: cdx.ComponentTypeLibrary, Name: "requests", Version: "2.0", BOMRef: "py", PackageURL: "pkg:pypi/requests@2.0"},
				{Type: cdx.ComponentTypeLibrary, Name: "app", Version: "1", BOMRef: "donor-app", PackageURL: "pkg:generic/app@1"},
			}

			bom, catalog, declared := publishedOf(ctx, base, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

			for _, record := range catalog.Records {
				for _, ref := range record.Components {
					Expect(declared).To(HaveKey(ref))
				}
			}
			Expect(lo.FromPtr(bom.Components)).To(ContainElement(HaveField("Name", "requests")),
				"the base this was merged with did survive the drop of superseded attribution")
		})

		// A patcher of the pipeline rewrites a component after the verification was
		// merged in: the Go patcher gives a module whose build left it at `(devel)`
		// the version a tag resolves to, changing its version and its purl. It is the
		// same component - the one the record named - and the catalog must still reach
		// it, at the purl it now carries.
		It("reaches a component a patcher rewrote after the verification", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			desc := pipelineImage(ctx, map[string][]byte{"/app/tool": goModuleRecordELF()})
			resolve := &resolveGoVersionsPatcher{version: "v1.2.3", modulePath: "example.invalid/app"}

			Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{},
				[]BOMPatcherInterface{resolve}, nil, true, "", nil, "")).To(Succeed())

			bom, err := step.GetImageBOM(ctx, "app", desc.Info)
			Expect(err).NotTo(HaveOccurred())
			catalog, err := nativegate.ReadCatalog([]*cdx.BOM{bom})
			Expect(err).NotTo(HaveOccurred())

			resolved, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool {
				return comp.Name == "example.invalid/app"
			})
			Expect(found).To(BeTrue())
			Expect(resolved.Version).To(Equal("v1.2.3"), "the patcher did rewrite the component")
			Expect(resolved.PackageURL).To(ContainSubstring("@v1.2.3"))
			Expect(catalog.Components).To(HaveKey(resolved.BOMRef),
				"the catalog reaches the component as the patcher left it")
			Expect(catalog.Records).To(HaveLen(1))
			Expect(catalog.Records[0].Components).To(ContainElement(resolved.BOMRef))
			// What the catalog holds is what was proven, not what the patcher made
			// of it afterwards.
			Expect(catalog.Components[resolved.BOMRef].Version).To(Equal("(devel)"))
		})

		It("leaves everything but the refs as the verification wrote it", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			_, catalog, _ := publishedOf(ctx, nil, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

			Expect(catalog.Schema).To(Equal("dk.catalog/v5"), "the schema the verification wrote, which is not the property name")
			record, found := lo.Find(catalog.Records, func(record nativegate.Record) bool { return record.Path == "/app/tool" })
			Expect(found).To(BeTrue())
			Expect(record.Origin).To(Equal("build"))
			Expect(record.SHA256).To(HavePrefix("sha256:"))
			Expect(record.Composition).NotTo(BeEmpty(), "the composition the record carries is untouched")
		})
	})

	It("keeps the inherited language packages, drops the package attribution the verification replaces, and shows the patchers one document", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{
			"/app/tool":         buildRecordELF(elf.ET_EXEC),
			"/etc/app/app.conf": []byte("key = value\n"),
		})

		base := cyclonedxutil.NewBOM()
		base.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "base", BOMRef: "base"}}
		base.Components = &[]cdx.Component{
			{Type: cdx.ComponentTypeLibrary, Name: "requests", Version: "2.0", BOMRef: "py", PackageURL: "pkg:pypi/requests@2.0", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}},
			{Type: cdx.ComponentTypeLibrary, Name: "left-pad", Version: "1.0", BOMRef: "js", PackageURL: "pkg:npm/left-pad@1.0"},
			{Type: cdx.ComponentTypeLibrary, Name: "github.com/x/y", Version: "v1.0", BOMRef: "go", PackageURL: "pkg:golang/github.com/x/y@v1.0"},
			{
				Type: cdx.ComponentTypeLibrary, Name: "github.com/x/embedded", Version: "v2.0", BOMRef: "go-embedded", PackageURL: "pkg:golang/github.com/x/embedded@v2.0",
				Properties: &[]cdx.Property{{Name: nativeCompositionProperty, Value: `{"kind":"go","locator":"github.com/x/embedded@v2.0"}`}},
			},
			{Type: cdx.ComponentTypeLibrary, Name: "zlib", Version: "1.3", BOMRef: "pm", PackageURL: "pkg:generic/zlib@1.3?containerfactoryversion=4.2"},
			{
				Type: cdx.ComponentTypeLibrary, Name: "musl", Version: "1.2", BOMRef: "origin", PackageURL: "pkg:generic/musl@1.2",
				Properties: &[]cdx.Property{{Name: cyclonedxutil.PropertyOriginalSource, Value: "source-id"}},
			},
			{Type: cdx.ComponentTypeFile, Name: "/scan/go.mod", BOMRef: "scanned-file"},
		}
		base.Dependencies = &[]cdx.Dependency{{Ref: "base", Dependencies: lo.ToPtr([]string{"py", "js", "go"})}}

		patcher := &recordingPatcher{}
		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, []BOMPatcherInterface{patcher}, nil, true, "", nil, "")).To(Succeed())

		Expect(saves).To(Equal(1), "one convergence reads the built image once")
		Expect(patcher.runs).To(Equal(1), "the patchers run once, on the whole document")
		Expect(patcher.purls).To(ContainElement("pkg:pypi/requests@2.0"))
		Expect(patcher.purls).To(ContainElement("pkg:npm/left-pad@1.0"))
		Expect(patcher.purls).To(ContainElement("pkg:golang/github.com/x/y@v1.0"))
		Expect(lo.SomeBy(patcher.purls, func(purl string) bool { return strings.Contains(purl, "source_kind=declared") })).
			To(BeTrue(), "the patchers see the components the verification established")

		bom, err := step.GetImageBOM(ctx, "app", desc.Info)
		Expect(err).NotTo(HaveOccurred())
		components := lo.FromPtr(bom.Components)
		purls := lo.Map(components, func(comp cdx.Component, _ int) string { return comp.PackageURL })

		Expect(purls).To(ContainElement("pkg:pypi/requests@2.0"))
		Expect(purls).To(ContainElement("pkg:npm/left-pad@1.0"))
		Expect(purls).To(ContainElement("pkg:golang/github.com/x/y@v1.0"))
		python, found := lo.Find(components, func(comp cdx.Component) bool { return comp.PackageURL == "pkg:pypi/requests@2.0" })
		Expect(found).To(BeTrue())
		Expect(python.Licenses).NotTo(BeNil(), "the license of an inherited language package survives the graft")

		Expect(purls).NotTo(ContainElement("pkg:generic/zlib@1.3?containerfactoryversion=4.2"), "the pm attribution of the donor is superseded")
		Expect(purls).NotTo(ContainElement("pkg:generic/musl@1.2"), "the donor's original-source attribution is superseded")
		Expect(purls).NotTo(ContainElement("pkg:golang/github.com/x/embedded@v2.0"), "the donor's composition claim is superseded, whatever purl names the component")
		Expect(lo.SomeBy(components, func(comp cdx.Component) bool {
			return comp.Type == cdx.ComponentTypeFile && comp.PackageURL == "" && comp.Name == "/scan/go.mod"
		})).To(BeFalse(), "the purl-less file component of a scan is dropped")

		Expect(lo.SomeBy(components, func(comp cdx.Component) bool {
			return comp.Type == cdx.ComponentTypeFile && comp.Name == "/app/tool"
		})).To(BeTrue(), "the verified file of the image is recorded")

		rootEdges := lo.Filter(lo.FromPtr(bom.Dependencies), func(dep cdx.Dependency, _ int) bool {
			return dep.Ref == bom.Metadata.Component.BOMRef
		})
		Expect(rootEdges).To(HaveLen(1), "the image declares one set of root dependencies")

		for _, property := range []string{"dk:catalog/v5", "dk:originals/v1"} {
			Expect(lo.CountBy(lo.FromPtr(bom.Metadata.Properties), func(prop cdx.Property) bool {
				return prop.Name == property
			})).To(Equal(1), property+" is carried once by the published document")
		}
	})

	It("drops a donor's composition claims about binaries this image does not hold", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

		base := cyclonedxutil.NewBOM()
		base.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "base", BOMRef: "base"}}
		base.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeLibrary, Name: "unimported", Version: "3.1", BOMRef: "urn:dk:component:stale",
				PackageURL: "pkg:generic/unimported@3.1?source_kind=declared&source_locator=https://example.invalid/unimported",
				Properties: &[]cdx.Property{{Name: "dk:source", Value: `{"kind":"declared","locator":"https://example.invalid/unimported"}`}},
			},
			{Type: cdx.ComponentTypeLibrary, Name: "requests", Version: "2.0", BOMRef: "py", PackageURL: "pkg:pypi/requests@2.0", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}},
			{Type: cdx.ComponentTypeLibrary, Name: "left-pad", Version: "1.0", BOMRef: "js", PackageURL: "pkg:npm/left-pad@1.0"},
		}

		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, nil, nil, true, "", nil, "")).To(Succeed())

		bom, err := step.GetImageBOM(ctx, "app", desc.Info)
		Expect(err).NotTo(HaveOccurred())
		components := lo.FromPtr(bom.Components)
		Expect(lo.SomeBy(components, func(comp cdx.Component) bool { return comp.Name == "unimported" })).
			To(BeFalse(), "a donor's claim about a binary this image does not hold is not a component of it")

		Expect(lo.Map(components, func(comp cdx.Component, _ int) string { return comp.PackageURL })).
			To(And(ContainElement("pkg:pypi/requests@2.0"), ContainElement("pkg:npm/left-pad@1.0")))
		Expect(lo.SomeBy(components, func(comp cdx.Component) bool {
			return comp.Name == "app" && strings.Contains(comp.PackageURL, "source_kind=declared")
		})).To(BeTrue(), "the composition of the binary this image does hold is recorded")
	})

	It("satisfies an os-pm directive only from a package bound to an original source", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/app/tool": buildRecordELF(elf.ET_EXEC)})

		err := step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, []string{"app"}, true, "", nil, "")
		Expect(err).To(MatchError(ContainSubstring("left no verified file in the image")),
			"the composition claim of a binary carries the declared name and version without proving the image is made of that package")
	})

	It("replaces a module read out of a verified binary while keeping every other attribution", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		tool := buildRecordELF(elf.ET_EXEC)
		toolDigest := sha256.Sum256(tool)
		desc := pipelineImage(ctx, map[string][]byte{"/app/tool": tool})

		binaryEvidence := func(path, digest string) *cdx.Evidence {
			return &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path, AdditionalContext: "werf:binary:v1:" + digest}}}
		}
		base := cyclonedxutil.NewBOM()
		base.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "base", BOMRef: "base"}}
		base.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeLibrary, Name: "example.com/guessed", Version: "v1.0.0", BOMRef: "guessed",
				PackageURL: "pkg:golang/example.com/guessed@v1.0.0", Evidence: binaryEvidence("/app/tool", "sha256:"+hex.EncodeToString(toolDigest[:])),
			},
			{
				Type: cdx.ComponentTypeLibrary, Name: "example.com/elsewhere", Version: "v1.0.0", BOMRef: "elsewhere",
				PackageURL: "pkg:golang/example.com/elsewhere@v1.0.0", Evidence: binaryEvidence("/app/tool", digestOfString("something else")),
			},
			{
				Type: cdx.ComponentTypeLibrary, Name: "example.com/declared", Version: "v1.0.0", BOMRef: "declared",
				PackageURL: "pkg:golang/example.com/declared@v1.0.0",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					{Location: "/src/go.mod", AdditionalContext: digestOfString("go.mod")},
				}},
			},
			{Type: cdx.ComponentTypeLibrary, Name: "requests", Version: "2.0", BOMRef: "py", PackageURL: "pkg:pypi/requests@2.0", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}},
			{Type: cdx.ComponentTypeLibrary, Name: "left-pad", Version: "1.0", BOMRef: "js", PackageURL: "pkg:npm/left-pad@1.0"},
		}
		base.Dependencies = &[]cdx.Dependency{{Ref: "base", Dependencies: lo.ToPtr([]string{"guessed", "elsewhere", "declared", "py", "js"})}}

		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, nil, nil, true, "", nil, "")).To(Succeed())

		bom, err := step.GetImageBOM(ctx, "app", desc.Info)
		Expect(err).NotTo(HaveOccurred())
		purls := lo.Map(lo.FromPtr(bom.Components), func(comp cdx.Component, _ int) string { return comp.PackageURL })

		Expect(purls).NotTo(ContainElement("pkg:golang/example.com/guessed@v1.0.0"),
			"what the binary itself says supersedes what a scanner read out of it")
		Expect(purls).To(ContainElement("pkg:golang/example.com/elsewhere@v1.0.0"),
			"a module attributed to other content than the verified binary holds is still a claim")
		Expect(purls).To(ContainElement("pkg:golang/example.com/declared@v1.0.0"), "file-based Go evidence stands")
		Expect(purls).To(ContainElement("pkg:pypi/requests@2.0"))
		Expect(purls).To(ContainElement("pkg:npm/left-pad@1.0"))

		python, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool { return comp.PackageURL == "pkg:pypi/requests@2.0" })
		Expect(found).To(BeTrue())
		Expect(python.Licenses).NotTo(BeNil())

		rootEdges, found := lo.Find(lo.FromPtr(bom.Dependencies), func(dep cdx.Dependency) bool { return dep.Ref == bom.Metadata.Component.BOMRef })
		Expect(found).To(BeTrue())
		Expect(lo.FromPtr(rootEdges.Dependencies)).NotTo(ContainElement("guessed"), "the dropped component leaves no dangling edge")
	})

	It("does not publish, or reuse, an SBOM for an image whose composition does not verify", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/app/tool": []byte("\x7fELF broken")})

		// Everything the cache key is made of is identical, so only the verification itself
		// stands between the published artifact and its reuse.
		provenance, err := resolveSBOMStageProvenance(ctx, desc, docker_registry.API().GetRepoImageConfigFile)
		Expect(err).NotTo(HaveOccurred())
		policyChecksum, err := sbomPolicyChecksum(nativegate.NewDefaultPolicy(ctx, "app"))
		Expect(err).NotTo(HaveOccurred())
		checksum := util.Sha256Hash(
			step.calculateStableChecksum(scanOpts, cyclonedxutil.MergeOpts{}, "", "", provenance),
			"policy", policyChecksum,
			"sources", sbomSourceImportsChecksum(nil),
		)
		cached := cyclonedxutil.NewBOM()
		restoreImageMetadata(cached, desc)
		cachedJSON, err := cyclonedxutil.ToJSON(cached)
		Expect(err).NotTo(HaveOccurred())
		Expect(sbomImage.PushSBOM(ctx, cachedJSON, repo, desc.Info.GetDigest(), "app", checksum, "", nil)).To(Succeed())

		err = step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, nil, true, "", nil, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("verify the composition of image app"))
	})

	// A descendant installs the package that owns a file of its base and the file is
	// written anew. The base's document states the digest the file used to have, which is
	// content this image carries nowhere.
	It("drops the base's whereabouts of a file the image replaced, and publishes the package as one it does not ship", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		base := cyclonedxutil.NewBOM()
		base.Components = &[]cdx.Component{
			{
				Type: cdx.ComponentTypeLibrary, Name: "ca-certificates", Version: "20210119", BOMRef: "base-ca",
				PackageURL: "pkg:deb/debian/ca-certificates@20210119?arch=all",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{
					Location: "/etc/ssl/certs/ca-certificates.crt", AdditionalContext: digestOfString("the bundle of the base\n"),
				}}},
			},
			{
				Type: cdx.ComponentTypeLibrary, Name: "libfoo", Version: "1.0", BOMRef: "base-libfoo",
				PackageURL: "pkg:deb/debian/libfoo@1.0?arch=amd64",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{
					Location: "/etc/app/app.conf", AdditionalContext: digestOfString("key = value\n"),
				}}},
			},
		}
		desc := pipelineImage(ctx, map[string][]byte{
			"/etc/ssl/certs/ca-certificates.crt": []byte("the bundle the descendant installed\n"),
			"/etc/app/app.conf":                  []byte("key = value\n"),
		})

		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, nil, nil, true, "", nil, "")).To(Succeed())

		bom, err := step.GetImageBOM(ctx, "app", desc.Info)
		Expect(err).NotTo(HaveOccurred())
		ca, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool { return comp.Name == "ca-certificates" })
		Expect(found).To(BeTrue())
		Expect(recordedPaths(ca)).To(BeEmpty(), "the image holds other bytes there, and the base's digest names content it carries nowhere")
		verdict, judged := judgement(ca)
		Expect(judged).To(BeTrue())
		Expect(verdict).To(Equal(shippedscope.PropertyShippedFalse))

		libfoo, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool { return comp.Name == "libfoo" })
		Expect(found).To(BeTrue())
		Expect(recordedPaths(libfoo)).To(ConsistOf("/etc/app/app.conf"))
		_, judged = judgement(libfoo)
		Expect(judged).To(BeFalse(), "the file it stands at holds what the base recorded")
	})

	It("refuses an image whose build left no stage provenance", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/etc/app/app.conf": []byte("key = value\n")})
		desc.StageID = imagePkg.NewStageID("other", 1)

		err := step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, nil, true, "", nil, "")
		Expect(err).To(MatchError(ContainSubstring("no-data: the stage provenance of the image is unknown")))
	})

	It("refuses an image that is not built from Stapel stages", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/etc/app/app.conf": []byte("key = value\n")})

		err := step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, nil, false, "", nil, "")
		Expect(err).To(MatchError(ContainSubstring("no-data: the composition of the image cannot be verified")))
	})

	It("reads a reserved source receipt path held by a directory as invalid, not as an absent receipt", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := pipelineImage(ctx, map[string][]byte{"/etc/app/app.conf": []byte("key = value\n")}, sources.DefaultPath)

		err := step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, nil, true, "", nil, "")
		Expect(err).To(MatchError(ContainSubstring("is a directory")))
	})
})

func digestOfString(body string) string {
	sum := sha256.Sum256([]byte(body))

	return "sha256:" + hex.EncodeToString(sum[:])
}

// buildRecordELF is the smallest ELF carrying an embedded build record, the form the
// verification reads a binary's composition from.
func recordELF(components ...shared.BuildComponent) []byte {
	GinkgoHelper()

	return buildRecordELFWith(elf.ET_EXEC, components)
}

func buildRecordELF(kind elf.Type) []byte {
	GinkgoHelper()

	return buildRecordELFWith(kind, []shared.BuildComponent{
		{ID: "app", Name: "app", Version: "1", Source: shared.BuildSource{Kind: "declared", Locator: "https://example.invalid/app"}},
	})
}

func buildRecordELFWith(kind elf.Type, components []shared.BuildComponent) []byte {
	GinkgoHelper()
	record := &shared.BuildRecord{
		Schema: "pm.buildinfo/v1", Artifact: "elf", Subject: "app", Complete: true,
		Profile:    shared.BuildProfile{ID: "c-static", Revision: "1", Platform: "linux/amd64"},
		Components: components,
		Inputs:     []shared.BuildInput{},
		Tools:      []shared.BuildTool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}},
	}
	payload, err := json.Marshal(map[string]any{"type": "pm", "sbom": record})
	Expect(err).NotTo(HaveOccurred())

	var note bytes.Buffer
	for _, n := range []uint32{4, uint32(len(payload)), 0xcafe1a7e} {
		Expect(binary.Write(&note, binary.LittleEndian, n)).To(Succeed())
	}
	_, err = note.Write(append([]byte("FDO\x00"), payload...))
	Expect(err).NotTo(HaveOccurred())
	for note.Len()%4 != 0 {
		Expect(note.WriteByte(0)).To(Succeed())
	}

	names := []byte("\x00.shstrtab\x00.note.package\x00")
	header := elf.Header64{
		Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:  uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Ehsize: 64, Shentsize: 64, Shnum: 3, Shstrndx: 1, Shoff: uint64(64 + note.Len() + len(names)),
	}
	var body bytes.Buffer
	for _, value := range []any{
		header, note.Bytes(), names,
		elf.Section64{},
		elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(64 + note.Len()), Size: uint64(len(names)), Addralign: 1},
		elf.Section64{Name: 11, Type: uint32(elf.SHT_NOTE), Off: 64, Size: uint64(note.Len()), Addralign: 4},
	} {
		Expect(binary.Write(&body, binary.LittleEndian, value)).To(Succeed())
	}

	return body.Bytes()
}

// resolveGoVersionsPatcher is the one thing the Go patcher of a real build does to a
// document: it resolves the version of a module the build left unresolved, and rewrites
// that component's version and purl.
type resolveGoVersionsPatcher struct {
	version    string
	modulePath string
}

func (p *resolveGoVersionsPatcher) Apply(_ context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	cyclonedxutil.ResolveUnknownGoVersions(bom, p.version, p.modulePath, nil, nil)

	return bom, nil
}

// goModuleRecordELF is an executable whose record names a Go module the build could not
// give a version to, which is what a build from an untagged checkout produces.
func goModuleRecordELF() []byte {
	GinkgoHelper()

	return recordELF(shared.BuildComponent{
		ID: "app", Name: "example.invalid/app", Version: "(devel)",
		Source: shared.BuildSource{Kind: "declared", Locator: "https://example.invalid/app"},
	})
}
