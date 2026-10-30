package stage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/foxboron/go-uefi/authenticode"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/smallstep/pkcs7"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/slug"
)

type signFilesContainerBackendStub struct {
	*ContainerBackendStub

	filesByTargetPlatform map[string]map[string][]byte
	// failSecondReadOf is a path whose second ReadFile — the one that wraps the
	// signature, after the digest pass — fails.
	failSecondReadOf string
}

var _ container_backend.ContainerBackend = (*signFilesContainerBackendStub)(nil)

func (backend *signFilesContainerBackendStub) OpenImageReader(_ context.Context, _ string, opts container_backend.ReadFileFromImageOpts) (container_backend.ImageReader, error) {
	files, found := backend.filesByTargetPlatform[opts.TargetPlatform]
	if !found {
		return nil, fmt.Errorf("no image built for platform %q", opts.TargetPlatform)
	}
	return &signFilesImageReaderStub{files: files, failSecondReadOf: backend.failSecondReadOf, reads: map[string]int{}}, nil
}

type signFilesImageReaderStub struct {
	files            map[string][]byte
	failSecondReadOf string
	reads            map[string]int
}

var _ container_backend.ImageReader = (*signFilesImageReaderStub)(nil)

func (r *signFilesImageReaderStub) ReadFile(_ context.Context, filePath string) ([]byte, error) {
	content, found := r.files[filePath]
	if !found {
		return nil, fmt.Errorf("read %s: %w", filePath, fs.ErrNotExist)
	}
	r.reads[filePath]++
	if filePath == r.failSecondReadOf && r.reads[filePath] == 2 {
		return nil, errors.New("layer vanished")
	}
	return content, nil
}

func (r *signFilesImageReaderStub) Glob(_ context.Context, pattern string) ([]string, error) {
	var matches []string
	for filePath := range r.files {
		matched, err := doublestar.Match(pattern, filePath)
		if err != nil {
			return nil, err
		}
		if matched {
			matches = append(matches, filePath)
		}
	}
	sort.Strings(matches)
	return matches, nil
}

func (r *signFilesImageReaderStub) ReadDir(_ context.Context, _, _ string, _ container_backend.ReadDirOpts) error {
	return fmt.Errorf("not implemented")
}

func (r *signFilesImageReaderStub) Close(_ context.Context) error {
	return nil
}

var _ = Describe("SignFilesStage", func() {
	newSigner := func(cn string) *signing.Signer {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		encryptedKey, err := encrypted.Encrypt(keyDER, nil)
		Expect(err).NotTo(HaveOccurred())

		signer, err := signing.NewSigner(context.Background(), signing.SignerOptions{
			KeyRef:  base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: signver.PrivateKeyPemType, Bytes: encryptedKey})),
			CertRef: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		})
		Expect(err).NotTo(HaveOccurred())
		return signer
	}

	enabledOptions := func(signer *signing.Signer) signing.FilesSigningOptions {
		options := signing.NewFilesSigningOptions(signer.Cert(), signer)
		options.Enabled = true
		return options
	}

	digestOfOptions := func(options signing.FilesSigningOptions, paths ...string) string {
		imageConfig := &config.StapelImageBase{}
		for _, p := range paths {
			imageConfig.Sign = append(imageConfig.Sign, &config.Sign{Path: p, After: "install"})
		}
		stage := GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{})
		Expect(stage).NotTo(BeNil())

		digest, err := stage.GetDependencies(context.Background(), nil, nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		contentDigest, err := stage.GetContentDependencies(context.Background(), nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(contentDigest).To(Equal(digest), "the content digest must be the same input set")
		return digest
	}

	digestOf := func(signer *signing.Signer, paths ...string) string {
		return digestOfOptions(enabledOptions(signer), paths...)
	}

	It("keeps the digest stable for the same paths and signer and changes it with either", func() {
		signerA := newSigner("a")
		signerB := newSigner("b")

		base := digestOf(signerA, "/out/x")
		Expect(digestOf(signerA, "/out/x")).To(Equal(base))
		Expect(digestOf(signerA, "/out/y")).NotTo(Equal(base), "a different signed path must change the digest")
		Expect(digestOf(signerB, "/out/x")).NotTo(Equal(base), "a different signing certificate must change the digest")

		authenticode := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", Format: config.SignFormatAuthenticode, After: "install"}}}
		authenticodeStage := GenerateSignFilesAfterInstallStage(authenticode, enabledOptions(signerA), &BaseStageOptions{})
		authenticodeDigest, err := authenticodeStage.GetDependencies(context.Background(), nil, nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(authenticodeDigest).NotTo(Equal(base), "the same path signed in another format is another stage")
	})

	It("binds the digest to the signature format, so a format change invalidates the cache", func() {
		signer := newSigner("a")

		imageConfig := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", After: "install"}}}
		stage := GenerateSignFilesAfterInstallStage(imageConfig, enabledOptions(signer), &BaseStageOptions{})
		expected := util.Sha256Hash(string(stage.Name()), "Format", signing.SignatureFormat, "Path", "/out/x", "Cert", signer.Cert())

		Expect(digestOf(signer, "/out/x")).To(Equal(expected), "the signature format must take part in the digest")
	})

	It("identifies the stage by the certificate alone, so no private key is needed to resolve it", func() {
		signer := newSigner("a")

		withoutKey := signing.NewFilesSigningOptions(signer.Cert(), nil)
		withoutKey.Enabled = true

		Expect(digestOfOptions(withoutKey, "/out/x")).To(Equal(digestOf(signer, "/out/x")))
	})

	It("keeps the signature of every platform in its own directory, so a concurrent platform build cannot replace a signature waiting for its container", func(ctx SpecContext) {
		const signedPath = "/out/ext.roothash"

		contentByTargetPlatform := map[string][]byte{
			"linux/amd64": []byte("amd64 root hash"),
			"linux/arm64": []byte("arm64 root hash"),
		}
		backend := &signFilesContainerBackendStub{
			ContainerBackendStub: NewContainerBackendStub(),
			filesByTargetPlatform: map[string]map[string][]byte{
				"linux/amd64": {signedPath: contentByTargetPlatform["linux/amd64"]},
				"linux/arm64": {signedPath: contentByTargetPlatform["linux/arm64"]},
			},
		}
		conveyor := NewConveyorStub(NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"), NewGiterminismInspectorStub()), nil, nil)
		imageConfig := &config.StapelImageBase{Name: "sysext", Sign: []*config.Sign{{Path: signedPath}}}
		imageTmpDir := filepath.Join(GinkgoT().TempDir(), "image", imageConfig.Name)
		options := enabledOptions(newSigner("a"))

		prepare := func(targetPlatform string) string {
			stage := GenerateSignFilesStage(imageConfig, options, &BaseStageOptions{
				TargetPlatform:   targetPlatform,
				ImageName:        imageConfig.Name,
				ImageTmpDir:      imageTmpDir,
				ContainerWerfDir: "/.werf",
			})
			Expect(stage).NotTo(BeNil())

			prevBuiltImage := container_backend.NewLegacyStageImage(nil, "previous-"+targetPlatform, backend, targetPlatform)
			prevBuiltImage.SetStageDesc(&image.StageDesc{Info: &image.Info{}})
			stageImage := NewStageImage(backend, prevBuiltImage.Name(), container_backend.NewLegacyStageImage(prevBuiltImage, "result-"+targetPlatform, backend, targetPlatform))

			Expect(stage.PrepareImage(ctx, conveyor, backend, &StageImage{Image: prevBuiltImage}, stageImage, nil)).To(Succeed())

			runOptions := stageImage.Builder.LegacyStapelStageBuilder().Container().RunOptions().(*container_backend.LegacyStageImageContainerOptions)
			var signaturesDirs []string
			for _, volume := range runOptions.Volume {
				hostPath, containerPath, _ := strings.Cut(volume, ":")
				if strings.HasPrefix(containerPath, "/.werf/sign/") {
					signaturesDirs = append(signaturesDirs, hostPath)
				}
			}
			Expect(signaturesDirs).To(HaveLen(1), "the stage must mount exactly one signatures directory")

			return filepath.Join(signaturesDirs[0], "0", path.Base(signedPath)+".p7s")
		}

		verifies := func(signaturePath string, content []byte) error {
			der, err := os.ReadFile(signaturePath)
			if err != nil {
				return err
			}
			p7, err := pkcs7.Parse(der)
			if err != nil {
				return err
			}
			p7.Content = content
			return p7.Verify()
		}

		amd64Signature := prepare("linux/amd64")
		Expect(verifies(amd64Signature, contentByTargetPlatform["linux/amd64"])).To(Succeed())

		arm64Signature := prepare("linux/arm64")
		Expect(verifies(arm64Signature, contentByTargetPlatform["linux/arm64"])).To(Succeed())
		Expect(verifies(amd64Signature, contentByTargetPlatform["linux/amd64"])).To(Succeed(),
			"preparing another platform must not overwrite the signature the first platform still has to install")
	})

	Describe("authenticode", func() {
		const targetPlatform = "linux/amd64"

		var (
			unsignedPE []byte
			signer     *signing.Signer
		)
		BeforeEach(func() {
			var err error
			unsignedPE, err = os.ReadFile("../signing/testdata/minimal.efi")
			Expect(err).NotTo(HaveOccurred())
			signer = newSigner("a")
		})

		prepare := func(ctx context.Context, files map[string][]byte, signs ...*config.Sign) (string, error) {
			backend := &signFilesContainerBackendStub{
				ContainerBackendStub:  NewContainerBackendStub(),
				filesByTargetPlatform: map[string]map[string][]byte{targetPlatform: files},
			}
			conveyor := NewConveyorStub(NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"), NewGiterminismInspectorStub()), nil, nil)
			imageConfig := &config.StapelImageBase{Name: "engine", Sign: signs}
			imageTmpDir := filepath.Join(GinkgoT().TempDir(), "image", imageConfig.Name)
			stage := GenerateSignFilesAfterInstallStage(imageConfig, enabledOptions(signer), &BaseStageOptions{
				TargetPlatform:   targetPlatform,
				ImageName:        imageConfig.Name,
				ImageTmpDir:      imageTmpDir,
				ContainerWerfDir: "/.werf",
			})
			Expect(stage).NotTo(BeNil())

			prevBuiltImage := container_backend.NewLegacyStageImage(nil, "previous", backend, targetPlatform)
			prevBuiltImage.SetStageDesc(&image.StageDesc{Info: &image.Info{}})
			stageImage := NewStageImage(backend, prevBuiltImage.Name(), container_backend.NewLegacyStageImage(prevBuiltImage, "result", backend, targetPlatform))

			if err := stage.PrepareImage(ctx, conveyor, backend, &StageImage{Image: prevBuiltImage}, stageImage, nil); err != nil {
				return "", err
			}
			return filepath.Join(imageTmpDir, "sign", slug.Slug(targetPlatform), string(stage.Name())), nil
		}

		It("replaces the PE binary in place with its signed copy, keeping it executable", func(ctx SpecContext) {
			files := map[string][]byte{"/out/boot.efi": unsignedPE}

			signaturesDir, err := prepare(ctx, files, &config.Sign{Path: "/out/boot.efi", Format: config.SignFormatAuthenticode, After: "install"})
			Expect(err).NotTo(HaveOccurred())

			script, err := os.ReadFile(filepath.Join(signaturesDir, "install.sh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(script)).To(MatchRegexp(`install -m 0755 \S+/0/boot\.efi /out/boot\.efi\n`), "the signed PE lands on the path of the unsigned one")
			Expect(string(script)).NotTo(ContainSubstring(".p7s"))

			signedPE, err := os.ReadFile(filepath.Join(signaturesDir, "0", "boot.efi"))
			Expect(err).NotTo(HaveOccurred())
			Expect(len(signedPE)).To(BeNumerically(">", len(unsignedPE)))
			bin, err := authenticode.Parse(bytes.NewReader(signedPE))
			Expect(err).NotTo(HaveOccurred())
			leafBlock, _ := pem.Decode([]byte(signer.Cert()))
			Expect(leafBlock).NotTo(BeNil())
			leaf, err := x509.ParseCertificate(leafBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			ok, err := bin.Verify(leaf)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("signs an embedded and a detached entry of the same stage each in its own format", func(ctx SpecContext) {
			files := map[string][]byte{
				"/out/boot.efi":        unsignedPE,
				"/out/rootfs.roothash": []byte("roothash"),
			}

			signaturesDir, err := prepare(ctx, files,
				&config.Sign{Path: "/out/boot.efi", Format: config.SignFormatAuthenticode, After: "install"},
				&config.Sign{Path: "/out/rootfs.roothash", Format: config.SignFormatDetachedPKCS7, After: "install"},
			)
			Expect(err).NotTo(HaveOccurred())

			script, err := os.ReadFile(filepath.Join(signaturesDir, "install.sh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(script)).To(ContainSubstring(" /out/boot.efi\n"))
			Expect(string(script)).To(ContainSubstring(" /out/rootfs.roothash.p7s\n"))
			Expect(string(script)).NotTo(ContainSubstring("/out/boot.efi.p7s"))
		})

		It("refuses a file that is not a PE binary", func(ctx SpecContext) {
			_, err := prepare(ctx, map[string][]byte{"/out/boot.efi": []byte("not a PE")}, &config.Sign{Path: "/out/boot.efi", Format: config.SignFormatAuthenticode, After: "install"})
			Expect(err).To(MatchError(HavePrefix(`sign /out/boot.efi of image "engine": `)))
			Expect(err).To(MatchError(ContainSubstring("parse PE")))
		})
	})

	Describe("glob patterns", func() {
		const targetPlatform = "linux/amd64"

		var failSecondReadOf string
		prepare := func(ctx context.Context, files map[string][]byte, signs ...*config.Sign) (string, error) {
			backend := &signFilesContainerBackendStub{
				ContainerBackendStub:  NewContainerBackendStub(),
				filesByTargetPlatform: map[string]map[string][]byte{targetPlatform: files},
				failSecondReadOf:      failSecondReadOf,
			}
			conveyor := NewConveyorStub(NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"), NewGiterminismInspectorStub()), nil, nil)
			imageConfig := &config.StapelImageBase{Name: "kernel", Sign: signs}
			imageTmpDir := filepath.Join(GinkgoT().TempDir(), "image", imageConfig.Name)
			stage := GenerateSignFilesAfterInstallStage(imageConfig, enabledOptions(newSigner("a")), &BaseStageOptions{
				TargetPlatform:   targetPlatform,
				ImageName:        imageConfig.Name,
				ImageTmpDir:      imageTmpDir,
				ContainerWerfDir: "/.werf",
			})
			Expect(stage).NotTo(BeNil())

			prevBuiltImage := container_backend.NewLegacyStageImage(nil, "previous", backend, targetPlatform)
			prevBuiltImage.SetStageDesc(&image.StageDesc{Info: &image.Info{}})
			stageImage := NewStageImage(backend, prevBuiltImage.Name(), container_backend.NewLegacyStageImage(prevBuiltImage, "result", backend, targetPlatform))

			if err := stage.PrepareImage(ctx, conveyor, backend, &StageImage{Image: prevBuiltImage}, stageImage, nil); err != nil {
				return "", err
			}
			return filepath.Join(imageTmpDir, "sign", slug.Slug(targetPlatform), string(stage.Name())), nil
		}

		verifies := func(signaturePath string, content []byte) error {
			der, err := os.ReadFile(signaturePath)
			if err != nil {
				return err
			}
			p7, err := pkcs7.Parse(der)
			if err != nil {
				return err
			}
			p7.Content = content
			return p7.Verify()
		}

		It("signs every regular file the pattern matches, in sorted order, and nothing else", func(ctx SpecContext) {
			files := map[string][]byte{
				"/out/lib/modules/6.12/kernel/net/b.ko":   []byte("module b"),
				"/out/lib/modules/6.12/kernel/a.ko":       []byte("module a"),
				"/out/lib/modules/6.12/modules.order":     []byte("not a module"),
				"/out/lib/modules/6.12/kernel/net/b.ko.d": []byte("not a module either"),
			}

			signaturesDir, err := prepare(ctx, files, &config.Sign{Path: "/out/lib/modules/**/*.ko", After: "install"})
			Expect(err).NotTo(HaveOccurred())

			script, err := os.ReadFile(filepath.Join(signaturesDir, "install.sh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(script)).To(ContainSubstring(" /out/lib/modules/6.12/kernel/a.ko.p7s\n"))
			Expect(string(script)).To(ContainSubstring(" /out/lib/modules/6.12/kernel/net/b.ko.p7s\n"))
			Expect(string(script)).NotTo(ContainSubstring("modules.order"))
			Expect(string(script)).NotTo(ContainSubstring("b.ko.d"))

			Expect(verifies(filepath.Join(signaturesDir, "0", "a.ko.p7s"), files["/out/lib/modules/6.12/kernel/a.ko"])).To(Succeed())
			Expect(verifies(filepath.Join(signaturesDir, "1", "b.ko.p7s"), files["/out/lib/modules/6.12/kernel/net/b.ko"])).To(Succeed())
		})

		It("treats every character but * literally, so file names with ?, [ or { need no escaping", func(ctx SpecContext) {
			files := map[string][]byte{
				"/out/lib[64]/a.ko":     []byte("a"),
				"/out/lib6/a.ko":        []byte("not under lib[64]"),
				"/out/file[1].bin":      []byte("literal path"),
				"/out/file1.bin":        []byte("would match [1] as a class"),
				"/out/{x}/what?.bin":    []byte("braces and question mark"),
				"/out/{x}/what!.bin":    []byte("would match ? as a wildcard"),
				"/out/lib[64]/b.ko.bak": []byte("not a .ko"),
			}

			signaturesDir, err := prepare(ctx, files,
				&config.Sign{Path: "/out/lib[64]/*.ko", After: "install"},
				&config.Sign{Path: "/out/file[1].bin", After: "install"},
				&config.Sign{Path: "/out/{x}/what?.b*", After: "install"},
			)
			Expect(err).NotTo(HaveOccurred())

			script, err := os.ReadFile(filepath.Join(signaturesDir, "install.sh"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(script)).To(ContainSubstring("/out/lib[64]/a.ko.p7s"))
			Expect(string(script)).To(ContainSubstring("/out/file[1].bin.p7s"))
			Expect(string(script)).To(ContainSubstring("/out/{x}/what?.bin.p7s"))
			Expect(string(script)).NotTo(ContainSubstring("lib6/"))
			Expect(string(script)).NotTo(ContainSubstring("file1.bin"))
			Expect(string(script)).NotTo(ContainSubstring("what!.bin"))
		})

		It("fails when the pattern matches no file, since a declared signature is a requirement of the image", func(ctx SpecContext) {
			_, err := prepare(ctx, map[string][]byte{"/out/notes.txt": []byte("x")}, &config.Sign{Path: "/out/**/*.ko", After: "install"})
			Expect(err).To(MatchError(ContainSubstring("`path: /out/**/*.ko` of sign in image \"kernel\" matches no file")))
		})

		It("rejects a file reached through two entries", func(ctx SpecContext) {
			_, err := prepare(ctx, map[string][]byte{"/out/a.ko": []byte("a")},
				&config.Sign{Path: "/out/*.ko", After: "install"},
				&config.Sign{Path: "/out/a.ko", After: "install"},
			)
			Expect(err).To(MatchError(ContainSubstring("file /out/a.ko of image \"kernel\" is signed by both `path: /out/*.ko` and `path: /out/a.ko` of sign")))
		})

		It("names the file a failure belongs to, not the first of the batch", func(ctx SpecContext) {
			failSecondReadOf = "/out/lib/modules/6.12/kernel/net/b.ko"
			DeferCleanup(func() { failSecondReadOf = "" })

			_, err := prepare(ctx, map[string][]byte{
				"/out/lib/modules/6.12/kernel/a.ko":     []byte("a"),
				"/out/lib/modules/6.12/kernel/net/b.ko": []byte("b"),
			}, &config.Sign{Path: "/out/**/*.ko", After: "install"})
			Expect(err).To(MatchError(HavePrefix(`sign /out/lib/modules/6.12/kernel/net/b.ko of image "kernel": `)))
			Expect(err).To(MatchError(ContainSubstring("layer vanished")))
		})

		It("rejects a matched file that is the signature of another file signed at the same stage", func(ctx SpecContext) {
			_, err := prepare(ctx, map[string][]byte{"/out/a": []byte("a"), "/out/a.p7s": []byte("old signature")}, &config.Sign{Path: "/out/*", After: "install"})
			Expect(err).To(MatchError(ContainSubstring("file /out/a.p7s of image \"kernel\" matched by `path: /out/*` of sign is the signature of /out/a signed at the same stage")))
		})
	})

	It("is generated only for the position the directive names and only when enabled", func() {
		imageConfig := &config.StapelImageBase{Sign: []*config.Sign{{Path: "/out/x", Before: "install"}}}
		options := enabledOptions(newSigner("a"))

		Expect(GenerateSignFilesAfterInstallStage(imageConfig, options, &BaseStageOptions{})).To(BeNil())
		Expect(GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{})).NotTo(BeNil())

		options.Enabled = false
		Expect(GenerateSignFilesBeforeInstallStage(imageConfig, options, &BaseStageOptions{})).To(BeNil())
	})
})
