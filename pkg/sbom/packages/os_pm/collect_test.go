package os_pm

import (
	"context"
	"errors"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/externalref"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("CollectBOM (AI)", func() {
	var (
		ctrl        *gomock.Controller
		mockBackend *mock.MockContainerBackend
		ctx         context.Context
		imageRef    string
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockBackend = mock.NewMockContainerBackend(ctrl)
		ctx = context.Background()
		imageRef = "test-image:latest"
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	It("reads the index and persisted version from the image", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryVersionPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte("v1.0.0-from-image\n"), nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())
		Expect(*bom.Components).To(HaveLen(6))
		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion=v1.0.0-from-image"))
		}
	})

	It("returns nil when index.json is empty", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte{}, nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).To(BeNil())
	})

	It("returns nil when index.json contains an empty JSON object", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte(`{}`), nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).To(BeNil())
	})

	It("returns an error when ReadFileFromImage fails", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return(nil, errors.New("image not found"))

		_, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("read /var/lib/pm/index.json from image"))
	})

	It("returns an error when index.json contains invalid JSON", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte(`{invalid}`), nil)

		_, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse pm installed JSON"))
	})

	It("reads the persisted version from the image", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryVersionPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte("v1.0.0-from-image\n"), nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion=v1.0.0-from-image"))
		}
	})

	It("ignores host PACKAGES_VERSION and propagates runtime component errors to enrichment", func() {
		Expect(os.Setenv("PACKAGES_VERSION", "host-version")).To(Succeed())
		DeferCleanup(os.Unsetenv, "PACKAGES_VERSION")

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryVersionPath, container_backend.ReadFileFromImageOpts{}).
			Return([]byte("image-version\n"), nil)

		bom, err := CollectAndMergeBOM(ctx, mockBackend, imageRef, nil)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())
		Expect((*bom.Components)[0].PackageURL).To(ContainSubstring("containerfactoryversion=image-version"))

		enricher := externalref.NewEnricher(func(_ context.Context, _ string) (*externalref.ResolveResult, error) {
			return nil, errors.New("resolver unavailable")
		})
		err = enricher.Enrich(ctx, bom)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolver unavailable"))
		Expect(err.Error()).To(ContainSubstring((*bom.Components)[0].Name))
	})

	It("sets the containerfactoryversion to empty string when the image file is unavailable", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryIndexPath, container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, ContainerFactoryVersionPath, container_backend.ReadFileFromImageOpts{}).
			Return(nil, errors.New("file not found"))

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion="))
		}
	})
})
