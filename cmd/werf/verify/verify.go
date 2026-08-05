package verify

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/cmd/werf/common"
	"github.com/werf/werf/v2/pkg/signature"
	"github.com/werf/werf/v2/pkg/tmp_manager"
	"github.com/werf/werf/v2/pkg/util/parallel"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

var commonCmdData common.CmdData

func NewCmd(ctx context.Context) *cobra.Command {
	ctx = common.NewContextWithCmdData(ctx, &commonCmdData)
	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   GetVerifyDocs().Use,
		Short:                 GetVerifyDocs().Short,
		Example:               GetVerifyDocs().Example,
		Long:                  common.GetLongCommandDescription(GetVerifyDocs().Long),
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			common.DocsLongMD: GetVerifyDocs().LongMD,
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			defer global_warnings.PrintGlobalWarnings(ctx)

			if err := common.ProcessLogOptions(&commonCmdData); err != nil {
				common.PrintHelp(cmd)
				return err
			}

			common.LogVersion()

			return common.LogRunningTime(func() error {
				return runMain(ctx)
			})
		},
	})

	common.SetupTmpDir(&commonCmdData, cmd, common.SetupTmpDirOptions{})
	common.SetupHomeDir(&commonCmdData, cmd, common.SetupHomeDirOptions{})

	common.SetupDockerConfig(&commonCmdData, cmd, "Command needs granted permissions to read, pull and push images into the specified repo, to pull base images")
	common.SetupInsecureRegistry(&commonCmdData, cmd)
	common.SetupSkipTlsVerifyRegistry(&commonCmdData, cmd)
	common.SetupContainerRegistryMirror(&commonCmdData, cmd)

	common.SetupVerificationOptions(&commonCmdData, cmd)
	common.SetupELFVerificationOptions(&commonCmdData, cmd)

	common.SetupLogOptions(&commonCmdData, cmd)
	common.SetupLogProjectDir(&commonCmdData, cmd)

	common.SetupParallelOptions(&commonCmdData, cmd, common.DefaultBuildParallelTasksLimit)

	return cmd
}

func runMain(ctx context.Context) error {
	_, ctx, err := common.InitCommonComponents(ctx, common.InitCommonComponentsOptions{
		Cmd:                &commonCmdData,
		InitWerf:           true,
		InitDockerRegistry: true,
	})
	if err != nil {
		return fmt.Errorf("component init error: %w", err)
	}

	defer func() {
		if err := tmp_manager.DelegateCleanup(ctx); err != nil {
			logboek.Context(ctx).Warn().LogF("Temporary files cleanup preparation failed: %s\n", err)
		}
	}()

	return run(ctx)
}

func run(ctx context.Context) error {
	verifyOptions, err := common.GetVerifyOptions(&commonCmdData)
	if err != nil {
		return fmt.Errorf("verify options error: %w", err)
	}

	if verifyOptions.References = common.GetImageReferences(&commonCmdData); len(verifyOptions.References) == 0 {
		return fmt.Errorf("no image references provided via --image-ref option")
	}

	parallelOptions := parallel.DoTasksOptions{
		MaxNumberOfWorkers: int(common.GetParallelTasksLimit(&commonCmdData)),
	}

	logboek.Context(ctx).Default().LogOptionalLn()
	if err = signature.Verify(ctx, verifyOptions, parallelOptions); err != nil {
		return err
	}

	return nil
}
