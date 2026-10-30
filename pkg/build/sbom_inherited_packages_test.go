package build

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"maps"
	"net/http/httptest"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
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
	"go.uber.org/mock/gomock"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

func debComponent(ref, name, version string) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: name, Version: version,
		PackageURL: "pkg:deb/debian/" + name + "@" + version + "?arch=amd64",
	}
}

func judgement(comp cdx.Component) (string, bool) {
	for _, property := range lo.FromPtr(comp.Properties) {
		if property.Name == shippedscope.PropertyShipped {
			return property.Value, true
		}
	}

	return "", false
}

var _ = Describe("Placing the packages an image inherited", func() {
	// The database of this image records what was installed into it, which is what its
	// base brought and what the build added. It knows nothing of the packages of an
	// image an import copied from, and the paths it holds for a name of its own would
	// be the wrong paths for that other image's package of the same name.
	It("is given the document of the base alone, and leaves the documents of imports untouched", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		base := cyclonedxutil.NewBOM()
		base.Components = &[]cdx.Component{debComponent("base-libfoo", "libfoo", "1.0")}
		imported := cyclonedxutil.NewBOM()
		imported.Components = &[]cdx.Component{
			debComponent("imported-libfoo", "libfoo", "9.9"),
			debComponent("imported-libquux", "libquux", "3.0"),
		}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, base)).To(Succeed())

		Expect(recordedPaths((*base.Components)[0])).To(ConsistOf("/app/lib/libfoo.so"))
		for _, comp := range *imported.Components {
			Expect(comp.Evidence).To(BeNil(), comp.BOMRef)
			_, judged := judgement(comp)
			Expect(judged).To(BeFalse(), comp.BOMRef+" is a package of another image, and this database says nothing of it")
		}
	})

	// An import of the whole of another image carries that image's own package
	// database with it; the one read here is this image's, and the version it records
	// for a name is no verdict on the version another image installed.
	It("leaves a package of another version an import brought in to be scoped as it arrived", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		imported := cyclonedxutil.NewBOM()
		imported.Components = &[]cdx.Component{debComponent("imported-libfoo", "libfoo", "9.9")}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, cyclonedxutil.NewBOM())).To(Succeed())

		scoped, err := scopeImportBOM(ctx, imported,
			[]nativegate.ImportScope{{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("libfoo"))
		_, judged := judgement((*scoped.Components)[0])
		Expect(judged).To(BeFalse())
	})

	// The verdict is written on the base document before the merge, and the scanned
	// document is marked after it. Between the two sits MarkNotShipped, which clears the
	// verdicts of a donor - and must leave standing the one this image just made about a
	// package of an ecosystem it cannot judge, or the whole pass would write nothing that
	// reaches the published document.
	It("publishes the verdict it made, through the order the convergence runs in", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		base := cyclonedxutil.NewBOM()
		base.Components = &[]cdx.Component{
			debComponent("base-libfoo", "libfoo", "1.0"),
			debComponent("base-gone", "libgone", "4.0"),
		}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, base)).To(Succeed())

		// From here on, the order of ConvergeWithMerge: merge the base into the
		// scanned document, canonicalize, then mark the file evidence of the result.
		scanned := cyclonedxutil.NewBOM()
		published, err := cyclonedxutil.MergeBOMs(ctx, scanned, cyclonedxutil.MergeOpts{BaseBOM: base})
		Expect(err).NotTo(HaveOccurred())
		cyclonedxutil.Canonicalize(ctx, published)
		filesets, err := shippedscope.CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		recordShippedScope(ctx, published, filesets, &shippedscope.ProducedFiles{}, "app")

		verdicts := map[string]string{}
		paths := map[string][]string{}
		for _, comp := range *published.Components {
			value, judged := judgement(comp)
			if judged {
				verdicts[comp.Name] = value
			}
			paths[comp.Name] = recordedPaths(comp)
		}
		Expect(verdicts).To(HaveKeyWithValue("libgone", shippedscope.PropertyShippedFalse),
			"the package the database never heard of is published as one this image does not ship")
		Expect(paths["libfoo"]).To(ConsistOf("/app/lib/libfoo.so"))
	})

	It("reads no database for an image whose base states nothing", func(specCtx SpecContext) {
		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())

		Expect((&sbomStep{}).placeInheritedPackages(logging.WithLogger(specCtx), "app", img, nil)).To(Succeed())
	})
})

var _ = Describe("What the document of an import source says about its own packages", func() {
	donorBOM := func(comps ...cdx.Component) *cdx.BOM {
		bom := cyclonedxutil.NewBOM()
		bom.Components = &comps

		return bom
	}

	// The donor image records libfoo under /app/lib and libbar under /srv/lib; the
	// import of these specs carries /app/bin only, so the projection that follows the
	// recompute decides which of them this image receives.
	recompute := func(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
		GinkgoHelper()
		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		database, err := shippedscope.DistroPackages(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		shippedscope.RecomputeDonorPackages(ctx, bom, database)

		return scopeImportBOM(ctx, bom, []nativegate.ImportScope{{
			Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/app/lib", ToPath: "/opt/lib",
		}})
	}

	// A supplier's document saying a package it ships is not shipped would hide that
	// package from this image and everything downstream of it.
	It("does not let the source's verdict hide a package the source's database records", func(specCtx SpecContext) {
		hidden := debComponent("libfoo", "libfoo", "1.0")
		hidden.Properties = &[]cdx.Property{{Name: shippedscope.PropertyShipped, Value: shippedscope.PropertyShippedFalse}}

		scoped, err := recompute(logging.WithLogger(specCtx), donorBOM(hidden))

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("libfoo"), "the import carries the files its own database names")
		_, judged := judgement((*scoped.Components)[0])
		Expect(judged).To(BeFalse())
	})

	// Most bases merged /lib into /usr/lib. A recipe naming the directory dpkg names -
	// which is the spelling a reader of the source's own package list would write - must
	// carry the package, though the file sits under the other spelling.
	DescribeTable("carries a package whichever spelling of a merged directory the import names",
		func(specCtx SpecContext, from string) {
			ctx := logging.WithLogger(specCtx)
			bom := donorBOM(debComponent("libfoo", "libfoo", "1.0"))

			img, err := mergedUsrDonorImage()
			Expect(err).NotTo(HaveOccurred())
			database, err := shippedscope.DistroPackages(ctx, img)
			Expect(err).NotTo(HaveOccurred())
			shippedscope.RecomputeDonorPackages(ctx, bom, database)

			scoped, err := scopeImportBOM(ctx, bom, []nativegate.ImportScope{{
				Backend: nativegate.ImportBackendCopyRecurse, FromPath: from, ToPath: "/opt/lib",
			}})

			Expect(err).NotTo(HaveOccurred())
			Expect(componentNames(scoped)).To(ConsistOf("libfoo"))
		},
		Entry("the directory dpkg names", "/lib/x86_64-linux-gnu"),
		Entry("the directory the image holds it under", "/usr/lib/x86_64-linux-gnu"),
		Entry("the file itself, as dpkg names it", "/lib/x86_64-linux-gnu/libfoo.so"),
	)

	It("drops a package the source's database does not record", func(specCtx SpecContext) {
		scoped, err := recompute(logging.WithLogger(specCtx), donorBOM(debComponent("ghost", "ghost", "9.9")))

		Expect(err).NotTo(HaveOccurred())
		Expect(scoped.Components).To(BeNil(), "this build decided it is not in the source, so the import carries none of it")
	})

	It("drops a package of the source the import carries no file of", func(specCtx SpecContext) {
		scoped, err := recompute(logging.WithLogger(specCtx), donorBOM(debComponent("libbar", "libbar", "2.0")))

		Expect(err).NotTo(HaveOccurred())
		Expect(scoped.Components).To(BeNil())
	})

	// Nothing read the source's database, so nobody can say where the package stands,
	// and a partial import of it is the question that has no answer.
	It("yields no data for a partial import of a source whose database it could not read", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		claimed := debComponent("libfoo", "libfoo", "1.0")
		claimed.Properties = &[]cdx.Property{{Name: shippedscope.PropertyShipped, Value: shippedscope.PropertyShippedFalse}}
		bom := donorBOM(claimed)

		img, err := imageWithoutPackageDatabase()
		Expect(err).NotTo(HaveOccurred())
		database, err := shippedscope.DistroPackages(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		shippedscope.RecomputeDonorPackages(ctx, bom, database)

		_, err = scopeImportBOM(ctx, bom, []nativegate.ImportScope{{
			Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/app/lib", ToPath: "/opt/lib",
		}})

		Expect(err).To(MatchError(ContainSubstring("no-data: the source states no whereabouts of libfoo")))
	})
})

func recordedPaths(comp cdx.Component) []string {
	paths := make([]string, 0)
	for _, occurrence := range lo.FromPtr(lo.FromPtr(comp.Evidence).Occurrences) {
		paths = append(paths, occurrence.Location)
	}

	return paths
}

// imageWithoutPackageDatabase is an image of the kind nothing here can read a package
// database out of: one built from scratch, or installed by a manager whose database is
// not read.
func imageWithoutPackageDatabase() (v1.Image, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "app/lib/libfoo.so", Mode: 0o644, Size: 3}); err != nil {
		return nil, err
	}
	if _, err := writer.Write([]byte("foo")); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	layer, err := fixtureLayer(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return mutate.AppendLayers(empty.Image, layer)
}

var _ = Describe("Reading the SBOM of an import source through the phase", func() {
	const targetPlatform = "linux/amd64"

	// The whole way through: a supplier image carrying a dpkg database, a published
	// document of it claiming one of its packages is not shipped, and the import that
	// copies the files of that package.
	It("decides a source's package claims from the source's own database", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		registryHost := strings.TrimPrefix(server.URL, "http://")

		sourceRepo := registryHost + "/supplier"
		sourceImg := sourceSnapshotImage([]sourceSnapshotFile{
			{Name: "var/lib/dpkg/status", Body: "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n"},
			{Name: "var/lib/dpkg/info/libfoo.list", Body: "/app/lib/libfoo.so\n"},
			{Name: "app/lib/libfoo.so", Body: "foo"},
		})
		sourceRef, err := name.NewTag(sourceRepo + ":latest")
		Expect(err).NotTo(HaveOccurred())
		Expect(remote.Write(sourceRef, sourceImg, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		sourceDigest, err := sourceImg.Digest()
		Expect(err).NotTo(HaveOccurred())

		hidden := debComponent("libfoo", "libfoo", "1.0")
		hidden.Properties = &[]cdx.Property{{Name: shippedscope.PropertyShipped, Value: shippedscope.PropertyShippedFalse}}
		sourceBOM := cyclonedxutil.NewBOM()
		sourceBOM.Components = &[]cdx.Component{hidden}
		sourceJSON, err := cyclonedxutil.ToJSON(sourceBOM)
		Expect(err).NotTo(HaveOccurred())
		Expect(sbomImage.PushSBOM(ctx, sourceJSON, sourceRepo, sourceDigest.String(), "", "checksum", "", nil)).To(Succeed())

		var saved bytes.Buffer
		Expect(tarball.Write(sourceRef, sourceImg, &saved)).To(Succeed())
		reference := sourceRepo + "@" + sourceDigest.String()
		info := &imagePkg.Info{Name: sourceRepo + ":latest", Repository: sourceRepo, RepoDigest: reference}

		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
		backend.EXPECT().GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).Return(info, nil).AnyTimes()
		backend.EXPECT().Pull(gomock.Any(), reference, container_backend.PullOpts{TargetPlatform: targetPlatform}).Return(nil).Times(1)
		backend.EXPECT().SaveImageToStream(gomock.Any(), reference).Return(io.NopCloser(bytes.NewReader(saved.Bytes())), nil).Times(1)

		imports := []*config.Import{{
			Export:        &config.Export{ExportBase: &config.ExportBase{Add: "/app/lib", To: "/opt/lib"}},
			Before:        string(stage.Install),
			ExternalImage: true,
			From:          sourceRepo + ":latest",
		}}
		img := &buildImage.Image{TargetPlatform: targetPlatform}
		stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform}
		img.SetStages(recordingImportBackend("copy-recurse",
			stage.GenerateDependenciesBeforeInstallStage(&config.StapelImageBase{Import: imports}, stageOpts)))
		phase := &BuildPhase{
			BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend, imagesTree: buildImage.NewImagesTree(nil, buildImage.ImagesTreeOptions{})}},
			sbomStep:  newSbomStep(backend, nil),
		}

		boms, _, captured, err := phase.collectImportImageSboms(ctx, img)

		Expect(err).NotTo(HaveOccurred())
		Expect(boms).To(HaveLen(1))
		Expect(componentNames(boms[0])).To(ConsistOf("libfoo"), "the source ships it, whatever its document claimed")
		_, judged := judgement((*boms[0].Components)[0])
		Expect(judged).To(BeFalse())
		Expect(recordedPaths((*boms[0].Components)[0])).To(ConsistOf("/app/lib/libfoo.so"))
		Expect(captured).To(HaveKey(reference), "the reading is handed on rather than made again")
	})
})

// mergedUsrDonorImage is a source image of the kind most bases are now: /lib is a symlink
// into /usr/lib, dpkg names the file under /lib, and the image holds it under /usr/lib.
func mergedUsrDonorImage() (v1.Image, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{
		Name: "lib", Typeflag: tar.TypeSymlink, Linkname: "usr/lib", Mode: 0o777,
	}); err != nil {
		return nil, err
	}
	files := map[string]string{
		"var/lib/dpkg/status":                "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
		"var/lib/dpkg/info/libfoo.list":      "/lib/x86_64-linux-gnu/libfoo.so\n",
		"usr/lib/x86_64-linux-gnu/libfoo.so": "foo",
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name]))}); err != nil {
			return nil, err
		}
		if _, err := writer.Write([]byte(files[name])); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	layer, err := fixtureLayer(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return mutate.AppendLayers(empty.Image, layer)
}
