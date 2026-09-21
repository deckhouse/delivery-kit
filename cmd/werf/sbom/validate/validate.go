package validate

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/cmd/werf/common"
	"github.com/werf/werf/v2/pkg/sbom/checker"
	"github.com/werf/werf/v2/pkg/sbom/ispras"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

var commonCmdData common.CmdData

func NewCmd(ctx context.Context) *cobra.Command {
	ctx = common.NewContextWithCmdData(ctx, &commonCmdData)

	var pathFlags []string
	var isprasFormatFlag string
	var checkVCSFlag bool
	var warningsNonFatalFlag bool

	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   "validate",
		Short:                 "Validate SBOM file against ISPRAS schemas",
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

			common.LogVersion()

			if err := validateFlags(pathFlags, isprasFormatFlag, checkVCSFlag); err != nil {
				common.PrintHelp(cmd)
				return err
			}

			isprasFormat, err := ispras.ParseFormat(isprasFormatFlag)
			if err != nil {
				common.PrintHelp(cmd)
				return err
			}

			return common.LogRunningTime(func() error {
				return runValidate(ctx, pathFlags, isprasFormat, checker.RunOptions{
					CheckVCS:         checkVCSFlag,
					WarningsNonFatal: warningsNonFatalFlag,
				})
			})
		},
	})

	common.SetupTmpDir(&commonCmdData, cmd, common.SetupTmpDirOptions{})
	common.SetupHomeDir(&commonCmdData, cmd, common.SetupHomeDirOptions{})

	common.SetupDockerConfig(&commonCmdData, cmd, "Command needs granted permissions to pull the ISPRAS SBOM checker image")
	common.SetupInsecureRegistry(&commonCmdData, cmd)
	common.SetupSkipTlsVerifyRegistry(&commonCmdData, cmd)
	common.SetupContainerRegistryMirror(&commonCmdData, cmd)

	common.SetupLogOptions(&commonCmdData, cmd)

	cmd.Flags().StringArrayVar(&pathFlags, "path", nil, "Path to CycloneDX JSON SBOM file (repeatable)")
	cmd.Flags().StringVar(&isprasFormatFlag, "ispras-format", "", "ISPRAS SBOM format: oss or container")
	cmd.Flags().BoolVar(&checkVCSFlag, "check-vcs", false, "Enable VCS URL validation")
	cmd.Flags().BoolVar(&warningsNonFatalFlag, "warnings-non-fatal", util.GetBoolEnvironmentDefaultFalse("WERF_WARNINGS_NON_FATAL"), "Do not fail validation on checker warnings; only errors set a non-zero exit code (default $WERF_WARNINGS_NON_FATAL or false)")

	return cmd
}

func runValidate(ctx context.Context, paths []string, isprasFormat ispras.Format, opts checker.RunOptions) error {
	_, ctx, err := common.InitCommonComponents(ctx, common.InitCommonComponentsOptions{
		Cmd:                         &commonCmdData,
		InitWerf:                    true,
		InitProcessContainerBackend: true,
	})
	if err != nil {
		return fmt.Errorf("component init error: %w", err)
	}

	return checker.Run(ctx, paths, isprasFormat, opts)
}

func validateFlags(path []string, isprasFormat string, checkVcs bool) error {
	if len(path) == 0 {
		return fmt.Errorf("required flag --path not set")
	}

	if isprasFormat == "" {
		return fmt.Errorf("required flag --ispras-format not set")
	}

	return nil
}
