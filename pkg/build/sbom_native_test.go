package build

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	buildimage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil/gost"
)

var _ = ginkgo.Describe("native SBOM cache", func() {
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
