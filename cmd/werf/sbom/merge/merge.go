package merge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/cmd/werf/common"
	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/sbom/convert"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/extract"
	"github.com/werf/werf/v2/pkg/tmp_manager"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

var commonCmdData common.CmdData

func NewCmd(ctx context.Context) *cobra.Command {
	ctx = common.NewContextWithCmdData(ctx, &commonCmdData)

	var input string
	var repo string
	var isprasFormatFlag string
	var appName string
	var appVersion string
	var manufacturer string
	var output string

	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   "merge",
		Short:                 "Merge per-image SBOMs into a product-level SBOM",
		Long:                  common.GetLongCommandDescription(GetDocs().Long),
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			common.DocsLongMD: GetDocs().LongMD,
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			defer global_warnings.PrintGlobalWarnings(ctx)

			if err := common.ProcessLogOptions(&commonCmdData); err != nil {
				common.PrintHelp(cmd)
				return err
			}

			if err := validateFlags(input, repo, isprasFormatFlag, appName, appVersion, manufacturer); err != nil {
				common.PrintHelp(cmd)
				return err
			}

			common.LogVersion()

			return common.LogRunningTime(func() error {
				return runMerge(ctx, mergeOptions{
					Input:        input,
					Repo:         repo,
					IsprasFormat: isprasFormatFlag,
					AppName:      appName,
					AppVersion:   appVersion,
					Manufacturer: manufacturer,
					Output:       output,
				})
			})
		},
	})

	cmd.Flags().StringVarP(&input, "input", "", "", "Path to JSON mapping file (image name -> sha256:digest)")
	cmd.Flags().StringVarP(&repo, "repo", "", os.Getenv("WERF_REPO"), "Container registry repository to pull SBOM images from")
	cmd.Flags().StringVarP(&isprasFormatFlag, "ispras-format", "", "", `ISPRAS SBOM format: "oss" or "container"`)
	cmd.Flags().StringVarP(&appName, "app-name", "", "", "Application/product name for the merged SBOM metadata")
	cmd.Flags().StringVarP(&appVersion, "app-version", "", "", "Application/product version for the merged SBOM metadata")
	cmd.Flags().StringVarP(&manufacturer, "manufacturer", "", "", "Manufacturer name for the merged SBOM metadata")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (defaults to stdout)")

	common.SetupTmpDir(&commonCmdData, cmd, common.SetupTmpDirOptions{})
	common.SetupHomeDir(&commonCmdData, cmd, common.SetupHomeDirOptions{})

	common.SetupDockerConfig(&commonCmdData, cmd, "Command needs granted permissions to pull images from the specified registry")
	common.SetupInsecureRegistry(&commonCmdData, cmd)
	common.SetupSkipTlsVerifyRegistry(&commonCmdData, cmd)
	common.SetupContainerRegistryMirror(&commonCmdData, cmd)

	common.SetupLogOptionsDefaultQuiet(&commonCmdData, cmd)

	return cmd
}

type mergeOptions struct {
	Input        string
	Repo         string
	IsprasFormat string
	AppName      string
	AppVersion   string
	Manufacturer string
	Output       string
}

func validateFlags(input, repo, isprasFormat, appName, appVersion, manufacturer string) error {
	var missing []string
	if input == "" {
		missing = append(missing, "--input")
	}
	if repo == "" {
		missing = append(missing, "--repo")
	}
	if isprasFormat == "" {
		missing = append(missing, "--ispras-format")
	}
	if appName == "" {
		missing = append(missing, "--app-name")
	}
	if appVersion == "" {
		missing = append(missing, "--app-version")
	}
	if manufacturer == "" {
		missing = append(missing, "--manufacturer")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required flag(s) not set: %v", missing)
	}

	if isprasFormat != "oss" && isprasFormat != "container" {
		return fmt.Errorf("--ispras-format must be \"oss\" or \"container\", got %q", isprasFormat)
	}

	return nil
}

func runMerge(ctx context.Context, opts mergeOptions) error {
	_, ctx, err := common.InitCommonComponents(ctx, common.InitCommonComponentsOptions{
		Cmd:                &commonCmdData,
		InitWerf:           true,
		InitDockerRegistry: true,
	})
	if err != nil {
		return fmt.Errorf("component init: %w", err)
	}

	defer func() {
		if err := tmp_manager.DelegateCleanup(ctx); err != nil {
			logboek.Context(ctx).Warn().LogF("Temporary files cleanup preparation failed: %s\n", err)
		}
	}()

	registry, err := common.CreateDockerRegistry(ctx, opts.Repo, *commonCmdData.InsecureRegistry, *commonCmdData.SkipTlsVerifyRegistry)
	if err != nil {
		return fmt.Errorf("create docker registry: %w", err)
	}

	mapping, err := readInputMapping(opts.Input)
	if err != nil {
		return fmt.Errorf("read input mapping: %w", err)
	}

	images, err := pullAndParseImages(ctx, registry, opts.Repo, mapping)
	if err != nil {
		return err
	}

	conv := &convert.Converter{
		Assembler: assemblerForFormat(opts.IsprasFormat),
	}

	result, err := conv.Convert(ctx, images, convert.ProductMeta{
		AppName:      opts.AppName,
		AppVersion:   opts.AppVersion,
		Manufacturer: opts.Manufacturer,
	})
	if err != nil {
		return fmt.Errorf("convert: %w", err)
	}

	jsonBytes, err := cyclonedxutil.ToJSON(result)
	if err != nil {
		return fmt.Errorf("serialize result: %w", err)
	}

	return writeOutput(jsonBytes, opts.Output)
}

func readInputMapping(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}

	var mapping map[string]string
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, fmt.Errorf("parse JSON from %q: %w", path, err)
	}

	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping in %q", path)
	}

	return mapping, nil
}

func pullAndParseImages(ctx context.Context, registry docker_registry.Interface, repo string, mapping map[string]string) ([]*convert.ImageSBOM, error) {
	var images []*convert.ImageSBOM

	for imageName, digest := range mapping {
		reference := fmt.Sprintf("%s@%s", repo, digest)

		logboek.Context(ctx).Default().LogFDetails("Pulling SBOM for %s (%s)\n", imageName, reference)

		bom, err := pullAndParseSBOM(ctx, registry, reference)
		if err != nil {
			return nil, fmt.Errorf("pull SBOM for %q (%s): %w", imageName, reference, err)
		}

		img, err := convert.NewImageSBOMFromCycloneDX16(ctx, imageName, bom)
		if err != nil {
			return nil, fmt.Errorf("parse SBOM for %q: %w", imageName, err)
		}

		images = append(images, img)
	}

	return images, nil
}

func pullAndParseSBOM(ctx context.Context, registry docker_registry.Interface, reference string) (*cdx.BOM, error) {
	var buf bytes.Buffer
	if err := registry.PullImageArchive(ctx, &buf, reference); err != nil {
		return nil, fmt.Errorf("pull image archive: %w", err)
	}

	archiveBytes := buf.Bytes()
	opener := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(archiveBytes)), nil
	}

	sbomJSON, err := extract.FromImageBytes(opener)
	if err != nil {
		return nil, fmt.Errorf("extract SBOM from image: %w", err)
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(sbomJSON)
	if err != nil {
		return nil, fmt.Errorf("parse CycloneDX BOM: %w", err)
	}

	return bom, nil
}

func assemblerForFormat(format string) convert.Assembler {
	switch format {
	case "container":
		return &convert.ISPRASContainerAssembler{}
	case "oss":
		return &convert.ISPRASOSSAssembler{}
	default:
		panic(fmt.Sprintf("bug: unknown format %q", format))
	}
}

func writeOutput(data []byte, outputPath string) error {
	if outputPath == "" {
		return logboek.Streams().DoErrorWithoutProxyStreamDataFormatting(func() error {
			_, err := os.Stdout.Write(data)
			return err
		})
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write output to %q: %w", outputPath, err)
	}

	return nil
}
