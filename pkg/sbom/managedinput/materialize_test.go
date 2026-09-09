package managedinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/container_backend"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("MaterializeCatalogerInputs", func() {
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

	It("materializes spec and lock adjacent, relative to the workdir, world-readable", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			Workdir:     "/app/api",
			SourcePaths: []string{"/app/api/go.mod", "/app/api/go.sum"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/api/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/api/go.sum", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("example.com/dep v1.0.0 h1:deadbeef\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		specPath := filepath.Join(dir, "go.mod")
		lockPath := filepath.Join(dir, "go.sum")

		specContent, err := os.ReadFile(specPath)
		Expect(err).To(Succeed())
		Expect(string(specContent)).To(Equal("module example.com/app\n"))

		lockContent, err := os.ReadFile(lockPath)
		Expect(err).To(Succeed())
		Expect(string(lockContent)).To(Equal("example.com/dep v1.0.0 h1:deadbeef\n"))

		Expect(filepath.Dir(specPath)).To(Equal(filepath.Dir(lockPath)),
			"spec and lock must be materialized in the same directory so the cataloger can link them")

		specInfo, err := os.Stat(specPath)
		Expect(err).To(Succeed())
		Expect(specInfo.Mode().Perm()&0o004).To(Equal(os.FileMode(0o004)), "spec must be world-readable")

		dirInfo, err := os.Stat(dir)
		Expect(err).To(Succeed())
		Expect(dirInfo.Mode().Perm()&0o005).To(Equal(os.FileMode(0o005)), "scan dir must be world-readable and traversable")
	})

	It("materializes only the spec when the directive declares no lock", func() {
		cataloger := scanner.Cataloger{
			Name:        "python-package-cataloger",
			Workdir:     "/app",
			SourcePaths: []string{"/app/requirements.txt"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/requirements.txt", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("flask==3.0.0\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		content, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
		Expect(err).To(Succeed())
		Expect(string(content)).To(Equal("flask==3.0.0\n"))
	})

	It("forwards the target platform to the image read", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			Workdir:     "/app",
			SourcePaths: []string{"/app/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{TargetPlatform: "linux/arm64"}).
			Return([]byte("module example.com/app\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "linux/arm64")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })
		Expect(dir).ToNot(BeEmpty())
	})

	It("fails naming the cataloger and path when a declared file is absent from the image", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			Workdir:     "/app",
			SourcePaths: []string{"/app/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return(nil, errors.New("no regular file at /app/go.mod"))

		_, _, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("go-module-file-cataloger"))
		Expect(err.Error()).To(ContainSubstring("/app/go.mod"))
	})
})
