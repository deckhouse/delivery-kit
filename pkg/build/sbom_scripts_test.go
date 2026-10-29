package build

import (
	"archive/tar"
	"bytes"
	"context"
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
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v3/pkg/docker_registry"
	imagePkg "github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/werf"
	"github.com/werf/werf/v3/test/mock"
)

var _ = Describe("Shipped scripts of an SBOM build", func() {
	const stageDigest = "scripts"

	var (
		repo     string
		backend  *mock.MockContainerBackend
		step     *sbomStep
		scanOpts scanner.ScanOptions
	)

	// The build marks what it ships executable; only the content decides whether a file is
	// a native artifact, so these fixtures carry the mode a shell leaves behind.
	executableImage := func(ctx context.Context, files map[string][]byte) *imagePkg.StageDesc {
		GinkgoHelper()
		var buf bytes.Buffer
		writer := tar.NewWriter(&buf)
		for _, path := range lo.Keys(files) {
			Expect(writer.WriteHeader(&tar.Header{Name: strings.TrimPrefix(path, "/"), Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(files[path]))})).To(Succeed())
			_, err := writer.Write(files[path])
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(writer.Close()).To(Succeed())
		layer, err := tarball.LayerFromReader(&buf)
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
				return io.NopCloser(bytes.NewReader(saved.Bytes())), nil
			}).AnyTimes()

		return &imagePkg.StageDesc{StageID: imagePkg.NewStageID(stageDigest, 1), Info: info}
	}

	BeforeEach(func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		Expect(werf.Init(GinkgoT().TempDir(), "")).To(Succeed())
		Expect(docker_registry.Init(ctx, false, false, nil, nil)).To(Succeed())
		server := httptest.NewServer(registry.New())
		DeferCleanup(server.Close)
		repo = strings.TrimPrefix(server.URL, "http://") + "/scripts"
		backend = mock.NewMockContainerBackend(gomock.NewController(GinkgoT()))
		step = &sbomStep{containerBackend: backend}
		scanOpts = scanner.DefaultSyftScanOptions()
		scanOpts.Commands[0].Catalogers = nil
	})

	It("verifies an image shipping executable scripts and keeps the evidence about them", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := executableImage(ctx, map[string][]byte{
			"/usr/local/bin/entrypoint.sh": []byte("#!/bin/sh\nexec /usr/local/bin/app \"$@\"\n"),
			"/usr/local/bin/migrate.py":    []byte("#!/usr/bin/env python3\nprint(\"migrate\")\n"),
		})

		base := cyclonedxutil.NewBOM()
		base.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeContainer, Name: "base", BOMRef: "base"}}
		base.Components = &[]cdx.Component{{
			Type: cdx.ComponentTypeLibrary, Name: "click", Version: "8.1", BOMRef: "py", PackageURL: "pkg:pypi/click@8.1",
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: "/usr/local/bin/migrate.py"}}},
		}}

		Expect(step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{BaseBOM: base}, nil, nil, true, "", nil, "")).
			To(Succeed(), "an executable text script is an ordinary file, not an unreadable native artifact")

		bom, err := step.GetImageBOM(ctx, "app", desc.Info)
		Expect(err).NotTo(HaveOccurred())
		components := lo.FromPtr(bom.Components)
		Expect(lo.Map(components, func(comp cdx.Component, _ int) string { return comp.PackageURL })).
			To(ContainElement("pkg:pypi/click@8.1"), "file evidence about a script survives the verification")
		Expect(lo.SomeBy(components, func(comp cdx.Component) bool {
			return comp.Type == cdx.ComponentTypeFile && strings.HasPrefix(comp.Name, "/usr/local/bin/")
		})).To(BeFalse(), "a script no original source binds is attributed to no package")
	})

	It("still refuses an executable whose format it cannot read", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		desc := executableImage(ctx, map[string][]byte{"/usr/local/bin/app": []byte("\x01\x02\x03\x04 opaque payload\n")})

		err := step.ConvergeWithMerge(ctx, "app", desc, scanOpts, cyclonedxutil.MergeOpts{}, nil, nil, true, "", nil, "")
		Expect(err).To(MatchError(ContainSubstring("unsupported: unknown binary or unsupported format /usr/local/bin/app")))
	})
})
