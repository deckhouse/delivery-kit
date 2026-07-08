package ls

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/cmd/werf/common"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/tmp_manager"
	"github.com/werf/werf/v2/pkg/werf/global_warnings"
)

var commonCmdData common.CmdData

func NewCmd(ctx context.Context) *cobra.Command {
	ctx = common.NewContextWithCmdData(ctx, &commonCmdData)

	var digestFlag string
	var tagFlag string

	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   "ls",
		Short:                 "List attestations attached to an image",
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

			return common.LogRunningTime(func() error {
				return runLs(ctx, digestFlag, tagFlag)
			})
		},
	})

	common.SetupTmpDir(&commonCmdData, cmd, common.SetupTmpDirOptions{})
	common.SetupHomeDir(&commonCmdData, cmd, common.SetupHomeDirOptions{})

	common.SetupRepoOptions(&commonCmdData, cmd, common.RepoDataOptions{OptionalRepo: false})

	common.SetupDockerConfig(&commonCmdData, cmd, "Command needs granted permissions to read images from the specified repo")
	common.SetupInsecureRegistry(&commonCmdData, cmd)
	common.SetupSkipTlsVerifyRegistry(&commonCmdData, cmd)
	common.SetupContainerRegistryMirror(&commonCmdData, cmd)

	common.SetupLogOptionsDefaultQuiet(&commonCmdData, cmd)
	common.SetupLogProjectDir(&commonCmdData, cmd)

	cmd.Flags().StringVarP(&digestFlag, "digest", "", "", "Digest of the image (e.g. sha256:abc123)")
	cmd.Flags().StringVarP(&tagFlag, "tag", "", "", "Tag of the image (resolved to digest)")

	return cmd
}

func runLs(ctx context.Context, digest, tag string) error {
	global_warnings.PostponeMultiwerfNotUpToDateWarning(ctx)

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

	repoAddr, err := commonCmdData.Repo.GetAddress()
	if err != nil {
		return fmt.Errorf("--repo is required: %w", err)
	}

	if digest == "" && tag == "" {
		return fmt.Errorf("specify --digest or --tag to identify the image")
	}
	if digest != "" && tag != "" {
		return fmt.Errorf("--digest and --tag are mutually exclusive")
	}

	if tag != "" {
		resolved, err := artifact.ResolveTag(ctx, repoAddr, tag)
		if err != nil {
			return err
		}
		digest = resolved
	}

	infos, err := attestation.List(ctx, repoAddr, digest)
	if err != nil {
		return fmt.Errorf("list attestations: %w", err)
	}

	if len(infos) == 0 {
		logboek.Context(ctx).Default().LogF("No attestations found\n")
		return nil
	}

	return logboek.Streams().DoErrorWithoutProxyStreamDataFormatting(func() error {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "PREDICATE TYPE\tDIGEST\tSIGNED")
		for _, info := range infos {
			signed := "no"
			if info.Signed {
				signed = "yes"
			}
			predType := info.PredicateType
			if predType == "" {
				predType = "(unknown)"
			}
			digestShort := info.Digest
			if len(digestShort) > 19 {
				digestShort = digestShort[:19] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", predType, digestShort, signed)
		}
		return w.Flush()
	})
}
