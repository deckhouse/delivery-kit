package managedinput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/logboek"
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

	It("materializes spec and lock under their full in-image path, adjacent, world-readable", func() {
		cataloger := scanner.Cataloger{
			Name:                "go-module-file-cataloger",
			SourcePaths:         []string{"/app/api/go.mod"},
			OptionalSourcePaths: []string{"/app/api/go.sum"},
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

		// The full in-image path is preserved so a dir:/scan scan records /app/api/go.mod,
		// not a workdir-relative /go.mod.
		specPath := filepath.Join(dir, "app", "api", "go.mod")
		lockPath := filepath.Join(dir, "app", "api", "go.sum")

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

		// The scan dir is nested in a parent that stays private to the invoking user, so on a
		// shared host other users cannot enumerate or read the extracted manifests.
		parentInfo, err := os.Stat(filepath.Dir(dir))
		Expect(err).To(Succeed())
		Expect(parentInfo.Mode().Perm()).To(Equal(os.FileMode(0o700)), "scan parent dir must be owner-only")
	})

	It("keeps the parent dir owner-only even under a permissive umask", func() {
		previousUmask := syscall.Umask(0o000)
		defer syscall.Umask(previousUmask)

		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			SourcePaths: []string{"/app/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		parentInfo, err := os.Stat(filepath.Dir(dir))
		Expect(err).To(Succeed())
		Expect(parentInfo.Mode().Perm()).To(Equal(os.FileMode(0o700)), "scan parent dir must be owner-only regardless of umask")
	})

	It("removes the private parent dir on cleanup", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			SourcePaths: []string{"/app/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())

		cleanup(ctx)

		_, err = os.Stat(filepath.Dir(dir))
		Expect(os.IsNotExist(err)).To(BeTrue(), "cleanup must remove the parent, not just the scan dir")
	})

	It("makes intermediate MkdirAll directories world-traversable under a restrictive umask", func() {
		// MkdirAll is umask-subject, so under umask 077 the app/ and app/api/ chain would be
		// 0700; the post-write walk must relax the whole tree. Without setting the umask the
		// assertion would pass for the wrong reason, since a default 022 umask already yields 0755.
		previousUmask := syscall.Umask(0o077)
		defer syscall.Umask(previousUmask)

		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			SourcePaths: []string{"/app/api/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/api/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		for _, d := range []string{dir, filepath.Join(dir, "app"), filepath.Join(dir, "app", "api")} {
			info, err := os.Stat(d)
			Expect(err).To(Succeed())
			Expect(info.Mode().Perm()&0o005).To(Equal(os.FileMode(0o005)),
				"intermediate dir %q must be world-readable and traversable — MkdirAll is umask-subject", d)
		}

		fileInfo, err := os.Stat(filepath.Join(dir, "app", "api", "go.mod"))
		Expect(err).To(Succeed())
		Expect(fileInfo.Mode().Perm()&0o004).To(Equal(os.FileMode(0o004)), "file must stay world-readable under a restrictive umask")
	})

	It("materializes only the spec when the directive declares no lock", func() {
		cataloger := scanner.Cataloger{
			Name:        "python-package-cataloger",
			SourcePaths: []string{"/app/requirements.txt"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/requirements.txt", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("flask==3.0.0\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		content, err := os.ReadFile(filepath.Join(dir, "app", "requirements.txt"))
		Expect(err).To(Succeed())
		Expect(string(content)).To(Equal("flask==3.0.0\n"))
	})

	It("keeps a materialized file inside the scan dir even if the source path contains ..", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
			SourcePaths: []string{"/app/../../../etc/go.mod"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/../../../etc/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		content, err := os.ReadFile(filepath.Join(dir, "etc", "go.mod"))
		Expect(err).To(Succeed())
		Expect(string(content)).To(Equal("module example.com/app\n"))
	})

	It("forwards the target platform to the image read", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
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

	It("skips an optional lock file that is absent from the image and warns about it", func() {
		// A go module with no dependencies has no go.sum; the old full-image scan simply did
		// not catalog it, and the build must not fail over its absence. But a lock that should
		// exist may also be gone (removed by a later stage, or a symlink), which silently drops
		// transitive dependencies — so the skip must be visible to the user.
		var output strings.Builder
		ctx := logboek.NewContext(ctx, logboek.NewLogger(&output, &output))

		cataloger := scanner.Cataloger{
			Name:                "go-module-file-cataloger",
			SourcePaths:         []string{"/app/go.mod"},
			OptionalSourcePaths: []string{"/app/go.sum"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.sum", container_backend.ReadFileFromImageOpts{}).
			Return(nil, fmt.Errorf("copy /app/go.sum from image %q: %w", imageRef, fs.ErrNotExist))

		dir, cleanup, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(Succeed())
		DeferCleanup(func() { cleanup(ctx) })

		content, err := os.ReadFile(filepath.Join(dir, "app", "go.mod"))
		Expect(err).To(Succeed())
		Expect(string(content)).To(Equal("module example.com/app\n"))

		_, err = os.Stat(filepath.Join(dir, "app", "go.sum"))
		Expect(os.IsNotExist(err)).To(BeTrue(), "the absent optional lock must not be materialized")

		Expect(output.String()).To(ContainSubstring("WARNING: lock file /app/go.sum not found in image"),
			"skipping a declared lock must be surfaced as a warning, not hidden at debug level")
		Expect(output.String()).To(ContainSubstring("go-module-file-cataloger"))
	})

	It("fails when reading an optional lock file errors for a reason other than absence", func() {
		// Only genuine absence may take the skip path. A transport or content-read failure
		// on a lock that exists must abort, or an incomplete SBOM would be published and cached.
		cataloger := scanner.Cataloger{
			Name:                "go-module-file-cataloger",
			SourcePaths:         []string{"/app/go.mod"},
			OptionalSourcePaths: []string{"/app/go.sum"},
		}
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.mod", container_backend.ReadFileFromImageOpts{}).
			Return([]byte("module example.com/app\n"), nil)
		mockBackend.EXPECT().
			ReadFileFromImage(ctx, imageRef, "/app/go.sum", container_backend.ReadFileFromImageOpts{}).
			Return(nil, fmt.Errorf("read /app/go.sum tar stream from image %q: %w", imageRef, io.ErrUnexpectedEOF))

		_, _, err := MaterializeCatalogerInputs(ctx, mockBackend, imageRef, cataloger, "")
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, io.ErrUnexpectedEOF)).To(BeTrue(), "the underlying read error must be preserved")
		Expect(err.Error()).To(ContainSubstring("go-module-file-cataloger"))
		Expect(err.Error()).To(ContainSubstring("/app/go.sum"))
	})

	It("fails naming the cataloger and path when a required spec is absent from the image", func() {
		cataloger := scanner.Cataloger{
			Name:        "go-module-file-cataloger",
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
