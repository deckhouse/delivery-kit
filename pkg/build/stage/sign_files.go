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

	"al.essio.dev/pkg/shellescape"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/container_backend"
	"github.com/werf/werf/v3/pkg/stapel"
)

const (
	SignFilesBeforeInstall StageName = "signFilesBeforeInstall"
	SignFilesAfterInstall  StageName = "signFilesAfterInstall"
	SignFilesBeforeSetup   StageName = "signFilesBeforeSetup"
	SignFilesAfterSetup    StageName = "signFilesAfterSetup"
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
	return generateSignFilesStage(imageBaseConfig, SignFilesBeforeInstall, &getImportsOptions{Before: Install}, options, baseStageOptions)
}

func GenerateSignFilesAfterInstallStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesAfterInstall, &getImportsOptions{After: Install}, options, baseStageOptions)
}

func GenerateSignFilesBeforeSetupStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesBeforeSetup, &getImportsOptions{Before: Setup}, options, baseStageOptions)
}

func GenerateSignFilesAfterSetupStage(imageBaseConfig *config.StapelImageBase, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	return generateSignFilesStage(imageBaseConfig, SignFilesAfterSetup, &getImportsOptions{After: Setup}, options, baseStageOptions)
}

func generateSignFilesStage(imageBaseConfig *config.StapelImageBase, name StageName, position *getImportsOptions, options signing.FilesSigningOptions, baseStageOptions *BaseStageOptions) *SignFilesStage {
	if !options.Enabled {
		return nil
	}

	var signs []*config.Sign
	for _, s := range imageBaseConfig.Sign {
		if (position.After != "" && s.After == string(position.After)) || (position.Before != "" && s.Before == string(position.Before)) {
			signs = append(signs, s)
		}
	}
	if len(signs) == 0 {
		return nil
	}

	return &SignFilesStage{
		BaseStage: NewBaseStage(name, baseStageOptions),
		signs:     signs,
		options:   options,
	}
}

func (s *SignFilesStage) GetDependencies(_ context.Context, _ Conveyor, _ container_backend.ContainerBackend, _, _ *StageImage, _ container_backend.BuildContextArchiver) (string, error) {
	return s.digest(), nil
}

func (s *SignFilesStage) GetContentDependencies(_ context.Context, _ Conveyor, _ container_backend.BuildContextArchiver) (string, error) {
	return s.digest(), nil
}

func (s *SignFilesStage) digest() string {
	args := []string{string(s.Name())}
	for _, sign := range s.signs {
		args = append(args, "Path", sign.Path)
	}
	args = append(args, "Cert", s.options.Signer().Cert())
	return util.Sha256Hash(args...)
}

func (s *SignFilesStage) PrepareImage(ctx context.Context, c Conveyor, cb container_backend.ContainerBackend, prevBuiltImage, stageImage *StageImage, buildContextArchive container_backend.BuildContextArchiver) error {
	if err := s.BaseStage.PrepareImage(ctx, c, cb, prevBuiltImage, stageImage, buildContextArchive); err != nil {
		return err
	}

	signaturesDir := filepath.Join(s.imageTmpDir, "sign", string(s.Name()))
	if err := os.MkdirAll(signaturesDir, os.ModePerm); err != nil {
		return fmt.Errorf("create signatures dir %s: %w", signaturesDir, err)
	}

	legacy := c.UseLegacyStapelBuilder(cb)
	var commands []string
	for _, sign := range s.signs {
		content, err := cb.ReadFileFromImage(ctx, prevBuiltImage.Image.Name(), sign.Path, container_backend.ReadFileFromImageOpts{TargetPlatform: s.targetPlatform})
		if err != nil {
			return fmt.Errorf("read %s to sign from image %q: %w", sign.Path, s.imageName, err)
		}

		var signature []byte
		if err := logboek.Context(ctx).Default().LogProcess("Signing %s", sign.Path).DoError(func() error {
			signature, err = signing.SignDetachedPKCS7(ctx, content, s.options.Signer())
			return err
		}); err != nil {
			return fmt.Errorf("sign %s of image %q: %w", sign.Path, s.imageName, err)
		}

		outputName := path.Base(sign.OutputPath())
		if legacy {
			hostPath := filepath.Join(signaturesDir, outputName)
			if err := os.WriteFile(hostPath, signature, 0o644); err != nil {
				return fmt.Errorf("write signature %s: %w", hostPath, err)
			}
			containerPath := path.Join(s.containerWerfDir, "sign", string(s.Name()), outputName)
			commands = append(commands,
				fmt.Sprintf("%s -p %s", stapel.MkdirBinPath(), shellescape.Quote(path.Dir(sign.OutputPath()))),
				fmt.Sprintf("%s -m 0644 %s %s", stapel.InstallBinPath(), shellescape.Quote(containerPath), shellescape.Quote(sign.OutputPath())),
			)
			continue
		}

		archive, err := singleFileTar(outputName, signature)
		if err != nil {
			return fmt.Errorf("pack signature of %s: %w", sign.Path, err)
		}
		stageImage.Builder.StapelStageBuilder().AddDataArchive(io.NopCloser(archive), container_backend.FileArchive, sign.OutputPath(), container_backend.AddDataArchiveOptions{})
	}

	if legacy {
		stageImage.Builder.LegacyStapelStageBuilder().Container().RunOptions().AddVolume(fmt.Sprintf("%s:%s:ro", signaturesDir, path.Join(s.containerWerfDir, "sign", string(s.Name()))))
		stageImage.Builder.LegacyStapelStageBuilder().Container().AddServiceRunCommands(commands...)
	}

	return nil
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
