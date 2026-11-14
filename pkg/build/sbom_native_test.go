package build

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	buildimage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
	sbomimage "github.com/werf/werf/v3/pkg/sbom/image"
	"github.com/werf/werf/v3/test/mock"
)

var _ = ginkgo.Describe("native SBOM cache", func() {
	ginkgo.DescribeTable("reuses the published artifact before reading cached stages", func(ctx ginkgo.SpecContext, valid bool) {
		gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
		server := httptest.NewServer(registry.New())
		ginkgo.DeferCleanup(server.Close)
		repository := strings.TrimPrefix(server.URL, "http://") + "/stages"
		ref, err := name.NewTag(repository + ":cached")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Write(ref, empty.Image, remote.WithContext(ctx))).To(gomega.Succeed())
		pin, err := empty.Image.Digest()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		checksum := nativeArtifactChecksum(pin.String(), "", gost.Config{})
		if !valid {
			checksum = "outdated"
		}
		gomega.Expect(sbomimage.PushSBOM(ctx, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), repository, pin.String(), "app", checksum, "linux/amd64", nil)).To(gomega.Succeed())
		ctrl := gomock.NewController(ginkgo.GinkgoT())
		backend := mock.NewMockContainerBackend(ctrl)
		external := mock.NewMockBOMPatcher(ctrl)
		directory := filepath.Join(ginkgo.GinkgoT().TempDir(), "unused")
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{ContainerBackend: backend, tmpDir: directory}}}
		img := &buildimage.Image{Name: "app", TargetPlatform: "linux/amd64", AnchorReused: true}
		img.SetContentTagDesc(&image.StageDesc{Info: &image.Info{Name: ref.Name(), Repository: repository, RepoDigest: repository + "@" + pin.String()}})
		needsStageRead := errors.New("stage read required")
		if !valid {
			backend.EXPECT().Pull(gomock.Any(), ref.Name(), container_backend.PullOpts{TargetPlatform: "linux/amd64"}).Return(needsStageRead)
		}
		err = phase.convergeNativeSBOM(ctx, img, cdx.NewBOM(), external, gost.Config{}, nil, "")
		if valid {
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(phase.convergeNativeSBOM(ctx, img, cdx.NewBOM(), external, gost.Config{}, nil, "")).To(gomega.Succeed())
		} else {
			gomega.Expect(err).To(gomega.MatchError(needsStageRead))
		}
		_, err = os.Stat(directory)
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
	}, ginkgo.Entry("valid checksum skips stage inspection", true), ginkgo.Entry("outdated checksum requires stage inspection", false))
	ginkgo.It("verifies scratch package state without imports or a precreated conveyor directory", func(ctx ginkgo.SpecContext) {
		ginkgo.GinkgoT().Setenv("WERF_SBOM_TRUSTED_INDEXES", "")
		gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
		server := httptest.NewServer(registry.New())
		ginkgo.DeferCleanup(server.Close)
		repository := strings.TrimPrefix(server.URL, "http://") + "/stages"
		id := image.NewStageID(strings.Repeat("a", 56), 1)
		record, err := json.Marshal(sbomStageRecord{Stage: stage.From, StageDigest: id.Digest})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg, err := empty.Image.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.OS, cfg.Architecture = "linux", "amd64"
		cfg.Config.Labels = map[string]string{image.WerfSBOMStageLabel: string(record)}
		saved, err := mutate.ConfigFile(empty.Image, cfg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ref, err := name.NewTag(repository + ":" + id.String())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remote.Write(ref, saved, remote.WithContext(ctx))).To(gomega.Succeed())
		directory := filepath.Join(ginkgo.GinkgoT().TempDir(), "conveyor", "not-created")
		_, err = os.Stat(directory)
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
		phase := &BuildPhase{BasePhase: BasePhase{Conveyor: &Conveyor{tmpDir: directory}}}
		packages, err := phase.nativePackages(ctx, &buildimage.Image{TargetPlatform: "linux/amd64"}, saved, &image.StageDesc{StageID: id, Info: &image.Info{Repository: repository, Name: ref.Name()}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(packages.Originals).To(gomega.BeEmpty())
		gomega.Expect(packages.Components).To(gomega.BeEmpty())
		remaining, err := os.ReadDir(directory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(remaining).To(gomega.BeEmpty())
	})
	ginkgo.It("invalidates only the SBOM artifact when GOST settings change", func() {
		first := nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueNo})
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueNo})).To(gomega.Equal(first))
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueNo, SecurityFunction: gost.GostValueNo})).NotTo(gomega.Equal(first))
		gomega.Expect(nativeArtifactChecksum("sha256:image", "signer", gost.Config{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes})).NotTo(gomega.Equal(first))
	})
	ginkgo.It("needs no intermediate ancestry when an image imports nothing", func() {
		phase := &BuildPhase{}
		result, err := phase.nativeImportOriginals(context.Background(), &buildimage.Image{}, empty.Image, &image.StageDesc{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(result.Originals).To(gomega.BeEmpty())
	})
})
