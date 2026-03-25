package validate

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/werf/werf/v2/cmd/werf/common"
)

var commonCmdData common.CmdData

func NewCmd(ctx context.Context) *cobra.Command {
	ctx = common.NewContextWithCmdData(ctx, &commonCmdData)

	var pathFlags []string
	var sbomTypeFlag string
	var checkVCSFlag bool

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

			if err := common.ProcessLogOptions(&commonCmdData); err != nil {
				common.PrintHelp(cmd)
				return err
			}

			if len(pathFlags) == 0 {
				common.PrintHelp(cmd)
				return fmt.Errorf("required flag --path not set")
			}

			if sbomTypeFlag == "" {
				common.PrintHelp(cmd)
				return fmt.Errorf("required flag --sbom-type not set")
			}

			if sbomTypeFlag != "oss" && sbomTypeFlag != "container" {
				common.PrintHelp(cmd)
				return fmt.Errorf("invalid --sbom-type value %q: must be one of oss, container", sbomTypeFlag)
			}

			return run(ctx, pathFlags, sbomTypeFlag, checkVCSFlag)
		},
	})

	common.SetupLogOptions(&commonCmdData, cmd)

	cmd.Flags().StringArrayVar(&pathFlags, "path", nil, "Path to CycloneDX JSON SBOM file (repeatable)")
	cmd.Flags().StringVar(&sbomTypeFlag, "sbom-type", "", "SBOM type: oss or container")
	cmd.Flags().BoolVar(&checkVCSFlag, "check-vcs", false, "Enable VCS URL validation")

	return cmd
}

func run(_ context.Context, _ []string, _ string, _ bool) error {
	return nil
}
