package build

import (
	"archive/tar"
	"bytes"
	"io"
	"net/http/httptest"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"go.uber.org/mock/gomock"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	sbomImage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("Installed inventory convergence", func() {
	DescribeTable("replaces an outdated cached BOM without any packages directive, then reuses the new inventory", func(specCtx SpecContext, oldVersion string) {
		ctx := logging.WithLogger(specCtx)
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		repo := strings.TrimPrefix(server.URL, "http://") + "/installed"
		ref, err := name.NewTag(repo + ":app")
		Expect(err).NotTo(HaveOccurred())

		metadataPath := "/usr/lib/python3/site-packages/inventory-1.0.dist-info/METADATA"
		metadata := "Metadata-Version: 2.1\nName: inventory\nVersion: 1.0\nLicense: MIT\n"
		var layer bytes.Buffer
		writer := tar.NewWriter(&layer)
		Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(metadataPath, "/"), Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(metadata))})).To(Succeed())
		_, err = io.WriteString(writer, metadata)
		Expect(err).NotTo(HaveOccurred())
		Expect(writer.Close()).To(Succeed())
		img, err := mutate.AppendLayers(empty.Image, static.NewLayer(layer.Bytes(), types.DockerUncompressedLayer))
		Expect(err).NotTo(HaveOccurred())
		Expect(remote.Write(ref, img, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))).To(Succeed())
		digest, err := img.Digest()
		Expect(err).NotTo(HaveOccurred())
		var saved bytes.Buffer
		Expect(tarball.Write(ref, img, &saved)).To(Succeed())
		info := &image.Info{Name: ref.Name(), Repository: repo, RepoDigest: repo + "@" + digest.String()}
		desc := &image.StageDesc{StageID: image.NewStageID("installed", 1), Info: info}

		opts := scanner.DefaultSyftScanOptions()
		opts.Commands[0].SourcePath = info.Name
		mergeOpts := cyclonedxutil.MergeOpts{}
		oldChecksum := util.Sha256Hash(
			oldVersion, "scan", opts.Checksum(), "merge", mergeOpts.Checksum(),
			"gost_attack_surface", mergeOpts.Gost.AttackSurface.String(),
			"gost_security_function", mergeOpts.Gost.SecurityFunction.String(),
			"signer", "", "platform", "", "produced", sbomProvenanceChecksum(sbomStageProvenance{}),
		)
		oldBOM := cyclonedxutil.NewBOM()
		restoreImageMetadata(oldBOM, desc)
		oldJSON, err := cyclonedxutil.ToJSON(oldBOM)
		Expect(err).NotTo(HaveOccurred())
		Expect(sbomImage.PushSBOM(ctx, oldJSON, repo, digest.String(), "app", oldChecksum, "", nil)).To(Succeed())

		scanned := cyclonedxutil.NewBOM()
		scanned.Components = &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, Name: "inventory", Version: "1.0", BOMRef: "inventory", PackageURL: "pkg:pypi/inventory@1.0",
			Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}},
		}}
		scannedJSON, err := cyclonedxutil.ToJSON(scanned)
		Expect(err).NotTo(HaveOccurred())
		ctrl := gomock.NewController(GinkgoT())
		backend := mock.NewMockContainerBackend(ctrl)
		backend.EXPECT().Pull(gomock.Any(), info.Name, gomock.Any()).Return(nil).Times(1)
		backend.EXPECT().SaveImageToStream(gomock.Any(), info.Name).Return(io.NopCloser(bytes.NewReader(saved.Bytes())), nil).Times(1)
		reader := mock.NewMockImageReader(ctrl)
		backend.EXPECT().OpenImageReader(gomock.Any(), info.Name, gomock.Any()).Return(reader, nil).Times(1)
		reader.EXPECT().ReadFile(gomock.Any(), metadataPath).Return([]byte(metadata), nil).Times(1)
		reader.EXPECT().Close(gomock.Any()).Return(nil).Times(1)
		backend.EXPECT().GenerateSBOM(gomock.Any(), gomock.Any()).Return(scannedJSON, nil).Times(1)
		step := &sbomStep{containerBackend: backend}

		for range 2 {
			Expect(step.ConvergeWithMerge(ctx, "app", desc, opts, mergeOpts, []BOMPatcherInterface{}, []string{}, true, "", nil, "")).To(Succeed())
			bom, err := step.GetImageBOM(ctx, "app", info)
			Expect(err).NotTo(HaveOccurred())
			Expect(lo.FromPtr(bom.Components)).To(HaveLen(1))
			Expect((*bom.Components)[0].PackageURL).To(Equal("pkg:pypi/inventory@1.0"))
			Expect((*bom.Components)[0].Licenses).NotTo(BeNil())
			Expect(bom.Metadata.Component.Type).To(Equal(cdx.ComponentTypeContainer))
			for _, dependency := range lo.FromPtr(bom.Dependencies) {
				if dependency.Ref == bom.Metadata.Component.BOMRef {
					Expect(lo.FromPtr(dependency.Dependencies)).To(BeEmpty(), "inventory does not declare an application dependency")
				}
			}
		}
	},
		Entry("declaration-only inventory", "14"),
		Entry("inventory before editable uncertainty", "15"),
		Entry("inventory before legacy bytecode evidence", "16"),
	)
})
