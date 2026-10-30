package stage

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"al.essio.dev/pkg/shellescape"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/slug"
	"github.com/werf/werf/v3/pkg/stapel"
)

const (
	SignFilesBeforeInstall StageName = "signFilesBeforeInstall"
	SignFilesAfterInstall  StageName = "signFilesAfterInstall"
	SignFilesBeforeSetup   StageName = "signFilesBeforeSetup"
	SignFilesAfterSetup    StageName = "signFilesAfterSetup"
	SignFiles              StageName = "signFiles"
)

// SignFilesStage signs the files the sign directive places at one position of the
// stage chain. The files are read out of the previous built image, signed on the host
// by the files signer and the detached PKCS#7 signatures are laid down next to them as
// a new layer; nothing of the user's runs in the stage container and it needs no network.
type SignFilesStage struct {
	*BaseStage

	signs   []*config.Sign
	options signing.FilesSigningOptions
}

var _ Interface = (*SignFilesStage)(nil)

func GenerateSignFilesBeforeInstallStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesBeforeInstall, atStageBoundary(&getImportsOptions{Before: Install}), options, baseStageOptions)
}

func GenerateSignFilesAfterInstallStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesAfterInstall, atStageBoundary(&getImportsOptions{After: Install}), options, baseStageOptions)
}

func GenerateSignFilesBeforeSetupStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesBeforeSetup, atStageBoundary(&getImportsOptions{Before: Setup}), options, baseStageOptions)
}

func GenerateSignFilesAfterSetupStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesAfterSetup, atStageBoundary(&getImportsOptions{After: Setup}), options, baseStageOptions)
}

// GenerateSignFilesStage covers the entries that name no stage: they are signed once the
// image's filesystem is complete, so that whatever imports the image gets the signature
// along with the file.
func GenerateSignFilesStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFiles, func(s *config.Sign) bool {
		return s.Before == "" && s.After == ""
	}, options, baseStageOptions)
}

func atStageBoundary(position *getImportsOptions) func(*config.Sign) bool {
	return func(s *config.Sign) bool {
		return (position.After != "" && s.After == string(position.After)) || (position.Before != "" && s.Before == string(position.Before))
	}
}

func generateSignFilesStage(imageBaseConfig *config.StapelImageBase, name StageName, matches func(*config.Sign) bool, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	if !options.Enabled {
		return nil
	}

	var signs []*config.Sign
	for _, s := range imageBaseConfig.Sign {
		if matches(s) {
			signs = append(signs, s)
		}
	}
	if len(signs) == 0 {
		return nil
	}

	stage := &SignFilesStage{
		BaseStage: NewBaseStage(name, baseStageOptions),
		signs:     signs,
		options:   options,
	}
	stage.SetNetworkOverride("none")
	return stage
}

func (s *SignFilesStage) GetDependencies(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, _ *StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	return s.digest(), nil
}

func (s *SignFilesStage) GetContentDependencies(_ context.Context, _ Conveyor, _ container_backend.BuildContextArchiver) (string, error) {
	return s.digest(), nil
}

func (s *SignFilesStage) digest() string {
	args := []string{string(s.Name()), "Format", signing.SignatureFormat}
	for _, sign := range s.signs {
		args = append(args, "Path", sign.Path)
		if sign.Embedded() {
			args = append(args, "Format", signing.AuthenticodeFormat)
		}
	}
	args = append(args, "Cert", s.options.Cert)
	return util.Sha256Hash(args...)
}

func (s *SignFilesStage) PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) error {
	if err := s.BaseStage.PrepareImage(ctx, c, cb, prevBuiltImage, stageImage, buildContextArchive); err != nil {
		return err
	}

	if s.options.Signer() == nil {
		return fmt.Errorf("image %q declares files to sign and this stage is not built yet: specify the private key with --sign-build-file-key", s.imageName)
	}

	// The platform variants of one image are independent graph nodes built in parallel and
	// share imageTmpDir: without the platform in the path the signature of one platform
	// replaces the other's before its container has installed it.
	signaturesDir := filepath.Join(s.imageTmpDir, "sign", slug.Slug(s.targetPlatform), string(s.Name()))
	if err := os.MkdirAll(signaturesDir, os.ModePerm); err != nil {
		return fmt.Errorf("create signatures dir %s: %w", signaturesDir, err)
	}

	reader, err := cb.OpenImageReader(ctx, prevBuiltImage.Image.Name(), container_backend.ReadFileFromImageOpts{TargetPlatform: s.targetPlatform})
	if err != nil {
		return fmt.Errorf("open image %q to sign files of image %q: %w", prevBuiltImage.Image.Name(), s.imageName, err)
	}
	defer func() {
		if err := reader.Close(ctx); err != nil {
			logboek.Context(ctx).Warn().LogF("WARNING: %s\n", err)
		}
	}()

	detached, embedded, err := s.expandSigns(ctx, reader)
	if err != nil {
		return err
	}

	legacy := c.UseLegacyStapelBuilder(cb)
	var installCommands []string
	outputIndex := 0
	// place puts one output of the stage into the image. A detached signature lands
	// next to its file as <file>.p7s; a signed PE replaces the file it was made from.
	place := func(output signOutput) error {
		outputName := path.Base(output.path)
		if legacy {
			// Two outputs can share a base name: keep every one in its own directory,
			// or the later overwrites the earlier and both destinations receive the
			// same content.
			entryDir := strconv.Itoa(outputIndex)
			outputIndex++
			if err := os.MkdirAll(filepath.Join(signaturesDir, entryDir), os.ModePerm); err != nil {
				return fmt.Errorf("create signature dir for %s: %w", output.path, err)
			}
			hostPath := filepath.Join(signaturesDir, entryDir, outputName)
			if err := os.WriteFile(hostPath, output.content, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", hostPath, err)
			}
			containerPath := path.Join(s.containerWerfDir, "sign", string(s.Name()), entryDir, outputName)
			installCommands = append(installCommands,
				fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), shellescape.Quote(path.Dir(output.path))),
				fmt.Sprintf("%s -m %04o %s %s", stapel.InstallBinPath(), output.mode, shellescape.Quote(containerPath), shellescape.Quote(output.path)),
			)
			return nil
		}
		archive, err := singleFileTar(outputName, output.content, output.mode)
		if err != nil {
			return fmt.Errorf("pack %s: %w", output.path, err)
		}
		stageImage.Builder.StapelStageBuilder().AddDataArchive(io.NopCloser(archive), container_backend.FileArchive, output.path, container_backend.AddDataArchiveOptions{})
		return nil
	}

	if len(detached) > 0 {
		var signatures [][]byte
		if err := logboek.Context(ctx).Default().LogProcess("Signing %d file(s)", len(detached)).DoError(func() error {
			for _, filePath := range detached {
				logboek.Context(ctx).Default().LogF("sign %s\n", filePath)
			}
			var signErr error
			signatures, signErr = signing.SignDetachedPKCS7Batch(ctx, &imageFiles{reader: reader, paths: detached}, s.options.Signer())
			return signErr
		}); err != nil {
			var contentErr *signing.ContentError
			if errors.As(err, &contentErr) {
				return fmt.Errorf("sign %s of image %q: %w", detached[contentErr.Index], s.imageName, contentErr.Err)
			}
			return fmt.Errorf("sign %d file(s) of image %q: %w", len(detached), s.imageName, err)
		}
		for i, filePath := range detached {
			if err := place(signOutput{path: config.SignatureOutputPath(filePath), content: signatures[i], mode: 0o644}); err != nil {
				return err
			}
		}
	}
	// One PE at a time: a UKI is tens of megabytes, and a signed copy is kept only until
	// it is placed.
	for _, filePath := range embedded {
		var signedPE []byte
		if err := logboek.Context(ctx).Default().LogProcess("Signing %s (authenticode)", filePath).DoError(func() error {
			pe, err := reader.ReadFile(ctx, filePath)
			if err != nil {
				return fmt.Errorf("read %s: %w", filePath, err)
			}
			signedPE, err = signing.SignAuthenticode(ctx, pe, s.options.Signer())
			return err
		}); err != nil {
			return fmt.Errorf("sign %s of image %q: %w", filePath, s.imageName, err)
		}
		if err := place(signOutput{path: filePath, content: signedPE, mode: 0o755}); err != nil {
			return err
		}
	}

	if legacy {
		// A pattern can expand to hundreds of files; a script keeps their install
		// commands out of the container's command line, which has a fixed size limit.
		const scriptName = "install.sh"
		if err := stapel.CreateScript(filepath.Join(signaturesDir, scriptName), installCommands); err != nil {
			return fmt.Errorf("create signatures install script: %w", err)
		}
		containerSignaturesDir := path.Join(s.containerWerfDir, "sign", string(s.Name()))
		stageImage.Builder.LegacyStapelStageBuilder().Container().RunOptions().AddVolume(fmt.Sprintf("%s:%s:ro", signaturesDir, containerSignaturesDir))
		stageImage.Builder.LegacyStapelStageBuilder().Container().AddServiceRunCommands(path.Join(containerSignaturesDir, scriptName))
	}

	return nil
}

// signOutput is a file the stage adds to the image.
type signOutput struct {
	path    string
	content []byte
	mode    int64
}

// expandSigns resolves the entries to the files to sign, in entry order, split by what
// the entry produces, and applies to the expanded set the conflict checks the config
// parser applies to literal paths.
func (s *SignFilesStage) expandSigns(ctx context.Context, reader container_backend.ImageReader) (detached, embedded []string, err error) {
	signByFile := map[string]*config.Sign{}
	for _, sign := range s.signs {
		matches := []string{sign.Path}
		if sign.IsPattern() {
			matches, err = reader.Glob(ctx, sign.Pattern())
			if err != nil {
				return nil, nil, fmt.Errorf("expand `path: %s` of sign in image %q: %w", sign.Path, s.imageName, err)
			}
			if len(matches) == 0 {
				return nil, nil, fmt.Errorf("`path: %s` of sign in image %q matches no file", sign.Path, s.imageName)
			}
		}
		for _, filePath := range matches {
			if other, exist := signByFile[filePath]; exist {
				return nil, nil, fmt.Errorf("file %s of image %q is signed by both `path: %s` and `path: %s` of sign", filePath, s.imageName, other.Path, sign.Path)
			}
			signByFile[filePath] = sign
			if sign.Embedded() {
				embedded = append(embedded, filePath)
			} else {
				detached = append(detached, filePath)
			}
		}
	}
	for _, filePath := range detached {
		if other, exist := signByFile[config.SignatureOutputPath(filePath)]; exist {
			return nil, nil, fmt.Errorf("file %s of image %q matched by `path: %s` of sign is the signature of %s signed at the same stage", config.SignatureOutputPath(filePath), s.imageName, other.Path, filePath)
		}
	}
	return detached, embedded, nil
}

func singleFileTar(name string, content []byte, mode int64) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// imageFiles reads the files to sign out of the image one at a time, so a stage of
// hundreds of files holds one in memory.
type imageFiles struct {
	reader container_backend.ImageReader
	paths  []string
}

var _ signing.ContentSource = (*imageFiles)(nil)

func (f *imageFiles) Len() int {
	return len(f.paths)
}

func (f *imageFiles) Content(ctx context.Context, i int) ([]byte, error) {
	content, err := f.reader.ReadFile(ctx, f.paths[i])
	if err != nil {
		return nil, fmt.Errorf("read %s from the image: %w", f.paths[i], err)
	}
	return content, nil
}
