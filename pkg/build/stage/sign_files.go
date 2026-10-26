package stage

import (
	"archive/tar"
	"bytes"
	"context"
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

	files, err := s.expandSigns(ctx, reader)
	if err != nil {
		return err
	}

	legacy := c.UseLegacyStapelBuilder(cb)
	var installCommands []string
	for i, filePath := range files {
		content, err := reader.ReadFile(ctx, filePath)
		if err != nil {
			return fmt.Errorf("read %s to sign from image %q: %w", filePath, s.imageName, err)
		}

		var signature []byte
		if err := logboek.Context(ctx).Default().LogProcess("Signing %s", filePath).DoError(func() error {
			var signErr error
			signature, signErr = signing.SignDetachedPKCS7(ctx, content, s.options.Signer())
			return signErr
		}); err != nil {
			return fmt.Errorf("sign %s of image %q: %w", filePath, s.imageName, err)
		}

		outputPath := config.SignatureOutputPath(filePath)
		outputName := path.Base(outputPath)
		if legacy {
			// Two signed files can share a base name: keep every signature in its own
			// directory, or the later one overwrites the earlier and both destinations
			// receive the same signature.
			entryDir := strconv.Itoa(i)
			if err := os.MkdirAll(filepath.Join(signaturesDir, entryDir), os.ModePerm); err != nil {
				return fmt.Errorf("create signature dir for %s: %w", filePath, err)
			}
			hostPath := filepath.Join(signaturesDir, entryDir, outputName)
			if err := os.WriteFile(hostPath, signature, 0o644); err != nil {
				return fmt.Errorf("write signature %s: %w", hostPath, err)
			}
			containerPath := path.Join(s.containerWerfDir, "sign", string(s.Name()), entryDir, outputName)
			installCommands = append(installCommands,
				fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), shellescape.Quote(path.Dir(outputPath))),
				fmt.Sprintf("%s -m 0644 %s %s", stapel.InstallBinPath(), shellescape.Quote(containerPath), shellescape.Quote(outputPath)),
			)
			continue
		}

		archive, err := singleFileTar(outputName, signature)
		if err != nil {
			return fmt.Errorf("pack signature of %s: %w", filePath, err)
		}
		stageImage.Builder.StapelStageBuilder().AddDataArchive(io.NopCloser(archive), container_backend.FileArchive, outputPath, container_backend.AddDataArchiveOptions{})
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

// expandSigns resolves the entries to the files to sign, in entry order, and applies to
// the expanded set the conflict checks the config parser applies to literal paths.
func (s *SignFilesStage) expandSigns(ctx context.Context, reader container_backend.ImageReader) ([]string, error) {
	var files []string
	signByFile := map[string]*config.Sign{}
	for _, sign := range s.signs {
		matches := []string{sign.Path}
		if sign.IsPattern() {
			var err error
			matches, err = reader.Glob(ctx, sign.Path)
			if err != nil {
				return nil, fmt.Errorf("expand `path: %s` of sign in image %q: %w", sign.Path, s.imageName, err)
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("`path: %s` of sign in image %q matches no file", sign.Path, s.imageName)
			}
		}
		for _, filePath := range matches {
			if other, exist := signByFile[filePath]; exist {
				return nil, fmt.Errorf("file %s of image %q is signed by both `path: %s` and `path: %s` of sign", filePath, s.imageName, other.Path, sign.Path)
			}
			signByFile[filePath] = sign
			files = append(files, filePath)
		}
	}
	for _, filePath := range files {
		if other, exist := signByFile[config.SignatureOutputPath(filePath)]; exist {
			return nil, fmt.Errorf("file %s of image %q matched by `path: %s` of sign is the signature of %s signed at the same stage", config.SignatureOutputPath(filePath), s.imageName, other.Path, filePath)
		}
	}
	return files, nil
}

func singleFileTar(name string, content []byte) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
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
