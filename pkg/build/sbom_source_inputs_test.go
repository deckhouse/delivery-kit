package build

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

var _ = Describe("SBOM source import inputs", func() {
	const targetPlatform = "linux/amd64"

	importElm := func(from, add, to string, include, exclude []string, before, after string) *config.Import {
		return &config.Import{
			Export:        &config.Export{ExportBase: &config.ExportBase{Add: add, To: to, IncludePaths: include, ExcludePaths: exclude}},
			From:          from,
			Before:        before,
			After:         after,
			ExternalImage: true,
		}
	}

	It("keeps the scope of every import directive while reading each source SBOM once", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		registryHost := strings.TrimPrefix(server.URL, "http://")

		sourceRepo := registryHost + "/builder"
		sourceRef, err := name.NewTag(sourceRepo + ":latest")
		Expect(err).NotTo(HaveOccurred())
		sourceImg := sourceSnapshotImage([]sourceSnapshotFile{{Name: "app/bin/tool", Body: "tool"}})
		Expect(remote.Write(sourceRef, sourceImg, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		sourceDigest, err := sourceImg.Digest()
		Expect(err).NotTo(HaveOccurred())

		sourceBOM := cyclonedxutil.NewBOM()
		sourceBOM.Components = &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, Name: "tool", Version: "1.0", BOMRef: "tool",
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/app/bin/tool"}}},
		}}
		sourceJSON, err := cyclonedxutil.ToJSON(sourceBOM)
		Expect(err).NotTo(HaveOccurred())
		Expect(sbomImage.PushSBOM(ctx, sourceJSON, sourceRepo, sourceDigest.String(), "", "checksum", "", nil)).To(Succeed())

		infos := map[string]*imagePkg.Info{
			sourceRepo + ":latest": {Name: sourceRepo + ":latest", Repository: sourceRepo, RepoDigest: sourceRepo + "@" + sourceDigest.String()},
			sourceRepo + ":alias":  {Name: sourceRepo + ":alias", Repository: sourceRepo, RepoDigest: sourceRepo + "@" + sourceDigest.String()},
		}
		backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		backend.EXPECT().HasStapelBuildSupport().Return(true).AnyTimes()
		backend.EXPECT().
			GetImageInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ any, ref string, _ container_backend.GetImageInfoOpts) (*imagePkg.Info, error) {
				return infos[ref], nil
			}).AnyTimes()

		img := &buildImage.Image{TargetPlatform: targetPlatform}
		baseConfig := &config.StapelImageBase{Import: []*config.Import{
			importElm(sourceRepo+":latest", "/app/bin", "/usr/local/bin", []string{"tool"}, nil, string(stage.Install), ""),
			importElm(sourceRepo+":alias", "/app/etc", "/etc", nil, []string{"secret"}, string(stage.Install), ""),
			importElm(registryHost+"/unknown:v1", "/out", "/srv", nil, nil, "", string(stage.Install)),
		}}
		stageOpts := &stage.BaseStageOptions{ImageName: "app", TargetPlatform: targetPlatform}
		img.SetStages(recordingImportBackend("copy-recurse",
			stage.GenerateDependenciesBeforeInstallStage(baseConfig, stageOpts),
			stage.GenerateDependenciesAfterInstallStage(baseConfig, stageOpts),
		))

		phase := &BuildPhase{
			BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend, imagesTree: buildImage.NewImagesTree(nil, buildImage.ImagesTreeOptions{})}},
			sbomStep:  newSbomStep(backend, nil),
		}

		boms, inputs, _, err := phase.collectImportImageSboms(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		Expect(boms).To(HaveLen(1), "the two references of one source image share a single SBOM artifact")

		Expect(inputs).To(HaveLen(3))
		Expect(inputs[0].Stage).To(Equal(stage.DependenciesBeforeInstall))
		Expect(inputs[0].Reference).To(Equal(sourceRepo + "@" + sourceDigest.String()))
		Expect(inputs[0].Scope).To(Equal(nativegate.ImportScope{FromPath: "/app/bin", ToPath: "/usr/local/bin", IncludePaths: []string{"tool"}}))
		Expect(inputs[0].BOM).To(BeIdenticalTo(boms[0]))

		Expect(inputs[1].Stage).To(Equal(stage.DependenciesBeforeInstall))
		Expect(inputs[1].Reference).To(Equal(inputs[0].Reference), "an alias of the same image is pinned to the same digest")
		Expect(inputs[1].Scope).To(Equal(nativegate.ImportScope{FromPath: "/app/etc", ToPath: "/etc", ExcludePaths: []string{"secret"}}))
		Expect(inputs[1].BOM).To(BeIdenticalTo(boms[0]), "the deduplicated SBOM still belongs to the second import")

		Expect(inputs[2].Reference).To(BeEmpty(), "an unresolved source is not guessed from its tag")
	})

	Describe("gate snapshots", func() {
		var snapshots []sbomSourceSnapshot
		var captured map[string]*sbomSourceImage

		BeforeEach(func() {
			snapshots = []sbomSourceSnapshot{
				{Stage: stage.From, Index: &shippedscope.FileIndex{}},
				{Stage: stage.Packages, LayerCount: 1, Index: &shippedscope.FileIndex{}, Receipt: &sources.Receipt{}},
				{Stage: stage.DependenciesBeforeInstall, LayerCount: 1, ImportBackend: "copy-recurse", Index: &shippedscope.FileIndex{}},
			}
			captured = map[string]*sbomSourceImage{
				"example.org/builder@sha256:aaa": {Index: &shippedscope.FileIndex{}, Receipt: &sources.Receipt{}},
			}
		})

		It("attaches the imports in build order to the stage that applies them", func() {
			inputs := []sbomSourceImportInput{
				{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{FromPath: "/a", ToPath: "/opt/a"}},
				{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{FromPath: "/b", ToPath: "/opt/b"}},
			}
			result, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(HaveLen(3))
			Expect(result[0].Stage).To(Equal("from"))
			Expect(result[1].Stage).To(Equal("packages"))
			Expect(result[1].Receipt).To(BeIdenticalTo(snapshots[1].Receipt))
			Expect(result[1].Imports).To(BeEmpty(), "a boundary shared with an earlier stage carries no import of its own")
			Expect(result[2].Stage).To(Equal("dependenciesBeforeInstall"))
			Expect(result[2].Imports).To(HaveLen(2))
			Expect(result[2].Imports[0].Scope.FromPath).To(Equal("/a"))
			Expect(result[2].Imports[1].Scope.FromPath).To(Equal("/b"))
			Expect(result[2].Imports[0].Index).To(BeIdenticalTo(captured["example.org/builder@sha256:aaa"].Index))
			Expect(result[2].Imports[0].Receipt).To(BeIdenticalTo(captured["example.org/builder@sha256:aaa"].Receipt))
		})

		It("uses the actual cached stage backend rather than the current builder", func() {
			snapshots[2].ImportBackend = "rsync"
			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/a", ToPath: "/opt/a"}}}
			result, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).NotTo(HaveOccurred())
			Expect(result[2].Imports[0].Scope.Backend).To(Equal(nativegate.ImportBackendRsync))
		})

		It("does not guess the backend of an old cached import stage", func() {
			snapshots[2].ImportBackend = ""
			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{FromPath: "/a", ToPath: "/opt/a"}}}
			_, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).To(MatchError(ContainSubstring("no-data: import backend")))
		})

		It("refuses an import the built image has no stage for", func() {
			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesAfterSetup, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{FromPath: "/a", ToPath: "/opt/a"}}}
			_, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).To(MatchError(ContainSubstring("no-data: stage dependenciesAfterSetup")))
		})

		It("refuses an import the build could not scope", func() {
			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/builder@sha256:aaa", Scope: nativegate.ImportScope{FromPath: "/a"}}}
			_, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).To(MatchError(ContainSubstring("carries no copy scope")))
		})

		It("refuses an import whose source image was not read", func() {
			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: "example.org/other@sha256:bbb", Scope: nativegate.ImportScope{FromPath: "/a", ToPath: "/opt/a"}}}
			_, err := sbomSourceGateSnapshots(snapshots, inputs, captured)
			Expect(err).To(MatchError(ContainSubstring("was not read")))
		})
	})

	Describe("source image capture", func() {
		It("reads each pinned source image once, with the receipt it carries", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())

			receipt := `{"version":1,"sources":[{"registry":"registry.example.test/pkg","packet":{"name":"x","version":"1","arch":["linux/amd64"],"digest":"sha256:` + strings.Repeat("a", 64) + `"},"platform":"linux/amd64"}]}`
			img := sourceSnapshotImage([]sourceSnapshotFile{
				{Name: strings.TrimPrefix(sources.DefaultPath, "/"), Body: receipt},
				{Name: "app/bin/tool", Body: "tool"},
			})
			ref, err := name.NewTag("example.org/builder:latest")
			Expect(err).NotTo(HaveOccurred())
			var saved bytes.Buffer
			Expect(tarball.Write(ref, img, &saved)).To(Succeed())

			const reference = "example.org/builder@sha256:aaa"
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			backend.EXPECT().Pull(gomock.Any(), reference, container_backend.PullOpts{TargetPlatform: targetPlatform}).Return(nil).Times(1)
			backend.EXPECT().SaveImageToStream(gomock.Any(), reference).Return(io.NopCloser(bytes.NewReader(saved.Bytes())), nil).Times(1)

			inputs := []sbomSourceImportInput{
				{Stage: stage.DependenciesBeforeInstall, Reference: reference, Scope: nativegate.ImportScope{FromPath: "/app/bin", ToPath: "/usr/local/bin"}},
				{Stage: stage.DependenciesAfterInstall, Reference: reference, Scope: nativegate.ImportScope{FromPath: "/app/bin", ToPath: "/opt/bin"}},
			}
			captured, err := captureSBOMSourceImages(ctx, backend, inputs, targetPlatform, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(captured).To(HaveLen(1))
			Expect(captured[reference].Index.Files).To(HaveKey("/app/bin/tool"))
			Expect(captured[reference].Receipt.Sources).To(HaveLen(1))
		})

		// The database travels with the same reading the snapshots come from: what the
		// source's own document claims about its packages is answered from it, and
		// walking the image a second time would answer the same.
		It("reads the package database the import source carries, from the same reading", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())

			img := sourceSnapshotImage([]sourceSnapshotFile{
				{Name: "var/lib/dpkg/status", Body: "Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n"},
				{Name: "var/lib/dpkg/info/libfoo.list", Body: "/app/lib/libfoo.so\n"},
				{Name: "app/lib/libfoo.so", Body: "foo"},
			})
			ref, err := name.NewTag("example.org/builder:latest")
			Expect(err).NotTo(HaveOccurred())
			var saved bytes.Buffer
			Expect(tarball.Write(ref, img, &saved)).To(Succeed())

			const reference = "example.org/supplier@sha256:ccc"
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			backend.EXPECT().Pull(gomock.Any(), reference, container_backend.PullOpts{TargetPlatform: targetPlatform}).Return(nil).Times(1)
			backend.EXPECT().SaveImageToStream(gomock.Any(), reference).Return(io.NopCloser(bytes.NewReader(saved.Bytes())), nil).Times(1)

			inputs := []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: reference, Scope: nativegate.ImportScope{FromPath: "/app", ToPath: "/opt"}}}
			captured, err := captureSBOMSourceImages(ctx, backend, inputs, targetPlatform, nil)

			Expect(err).NotTo(HaveOccurred())
			database := captured[reference].Database
			Expect(database.Present).To(BeTrue())
			entry := database.Packages[shippedscope.DistroPackageKey("libfoo", "1.0", "amd64")]
			Expect(shippedscope.InheritedPackagePaths(entry)).To(ConsistOf("/app/lib/libfoo.so"))
		})

		// The backend is asked for nothing it was asked for already: a source read while
		// its document was being scoped is the same image at the same digest.
		It("reads no import source twice when one reading was already made", func(specCtx SpecContext) {
			ctx := logging.WithLogger(specCtx)
			const reference = "example.org/supplier@sha256:ddd"
			already := map[string]*sbomSourceImage{reference: {Index: &shippedscope.FileIndex{}}}
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))

			captured, err := captureSBOMSourceImages(ctx, backend,
				[]sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall, Reference: reference, Scope: nativegate.ImportScope{FromPath: "/a", ToPath: "/b"}}},
				targetPlatform, already)

			Expect(err).NotTo(HaveOccurred())
			Expect(captured[reference]).To(BeIdenticalTo(already[reference]))
		})

		It("refuses an import whose source image the build could not pin", func(ctx SpecContext) {
			backend := mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
			_, err := captureSBOMSourceImages(ctx, backend, []sbomSourceImportInput{{Stage: stage.DependenciesBeforeInstall}}, targetPlatform, nil)
			Expect(err).To(MatchError(ContainSubstring("no-data: import source of stage dependenciesBeforeInstall is not pinned")))
		})
	})
})
