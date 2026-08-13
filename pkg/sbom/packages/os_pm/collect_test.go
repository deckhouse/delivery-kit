package os_pm

import (
	"context"
	"errors"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/container_backend"
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
		os.Unsetenv("PACKAGES_VERSION")
	})

	It("reads /var/lib/pm/index.json from image and returns a BOM (with PACKAGES_VERSION set)", func() {
		os.Setenv("PACKAGES_VERSION", "v1.0.0-test-env")
		defer os.Unsetenv("PACKAGES_VERSION")

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())
		Expect(*bom.Components).To(HaveLen(6))
	})

	It("returns nil when index.json is empty", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return([]byte{}, nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).To(BeNil())
	})

	It("returns nil when index.json contains an empty JSON object", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return([]byte(`{}`), nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).To(BeNil())
	})

	It("returns an error when ReadFileFromImage fails", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return(nil, errors.New("image not found"))

		_, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("read /var/lib/pm/index.json from image"))
	})

	It("returns an error when index.json contains invalid JSON", func() {
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return([]byte(`{invalid}`), nil)

		_, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("parse pm installed JSON"))
	})

	It("uses PACKAGES_VERSION env var when set, skipping image read for factory version", func() {
		os.Setenv("PACKAGES_VERSION", "v2.0.0-env")
		defer os.Unsetenv("PACKAGES_VERSION")

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion=v2.0.0-env"))
		}
	})

	It("falls back to reading /var/lib/pm/container-factory-version from image when env is empty", func() {
		os.Unsetenv("PACKAGES_VERSION")

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/container-factory-version", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("v1.0.0-from-image\n"), nil)

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion=v1.0.0-from-image"))
		}
	})

	It("sets the containerfactoryversion to empty string when both env and image file are unavailable", func() {
		os.Unsetenv("PACKAGES_VERSION")

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/index.json", container_backend.ReadFileFromImageOpts{}).
			Return(examplePmInstalledJSON, nil)

		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/var/lib/pm/container-factory-version", container_backend.ReadFileFromImageOpts{}).
			Return(nil, errors.New("file not found"))

		bom, err := CollectBOM(ctx, mockBackend, imageRef)
		Expect(err).To(Succeed())
		Expect(bom).ToNot(BeNil())

		for _, comp := range *bom.Components {
			Expect(comp.PackageURL).To(ContainSubstring("containerfactoryversion="))
		}
	})
})
