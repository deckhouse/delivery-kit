package sign

import (
	"context"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

	var predicateFlag string
	var typeFlag string
	var digestFlag string
	var tagFlag string
	var imageFlag string

	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   "sign",
		Short:                 "Create a signed attestation and attach it to an image",
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

			if predicateFlag == "" {
				return fmt.Errorf("--predicate is required")
			}
			if typeFlag == "" {
				return fmt.Errorf("--type is required")
			}

			common.LogVersion()

			return common.LogRunningTime(func() error {
				return runSign(ctx, predicateFlag, typeFlag, digestFlag, tagFlag, imageFlag)
			})
		},
	})

	common.SetupTmpDir(&commonCmdData, cmd, common.SetupTmpDirOptions{})
	common.SetupHomeDir(&commonCmdData, cmd, common.SetupHomeDirOptions{})

	common.SetupRepoOptions(&commonCmdData, cmd, common.RepoDataOptions{OptionalRepo: false})

	common.SetupDockerConfig(&commonCmdData, cmd, "Command needs granted permissions to read and push images into the specified repo")
	common.SetupInsecureRegistry(&commonCmdData, cmd)
	common.SetupSkipTlsVerifyRegistry(&commonCmdData, cmd)
	common.SetupContainerRegistryMirror(&commonCmdData, cmd)

	common.SetupSigningOptions(&commonCmdData, cmd)

	common.SetupLogOptions(&commonCmdData, cmd)
	common.SetupLogProjectDir(&commonCmdData, cmd)

	cmd.Flags().StringVarP(&predicateFlag, "predicate", "", "", "Path to the predicate file (required)")
	cmd.Flags().StringVarP(&typeFlag, "type", "", "", fmt.Sprintf("Predicate type: %s, or a full URI (required)", attestation.PredicateTypeHelp()))
	cmd.Flags().StringVarP(&digestFlag, "digest", "", "", "Digest of the parent image (e.g. sha256:abc123)")
	cmd.Flags().StringVarP(&tagFlag, "tag", "", "", "Tag of the parent image (resolved to digest)")
	cmd.Flags().StringVarP(&imageFlag, "image", "", "", "Image name for artifact indexing (optional; disambiguates images sharing the same digest)")

	return cmd
}

func runSign(ctx context.Context, predicatePath, predicateType, digest, tag, imageName string) error {
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
		return fmt.Errorf("specify --digest or --tag to identify the parent image")
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

	predicateBytes, err := os.ReadFile(predicatePath)
	if err != nil {
		return fmt.Errorf("read predicate file: %w", err)
	}

	keyRef := ""
	if commonCmdData.SignKey != nil {
		keyRef = *commonCmdData.SignKey
	}
	if keyRef == "" {
		return fmt.Errorf("signing key is required (specify --sign-key)")
	}

	signer, err := attestation.LoadSigner(keyRef, cryptoutils.SkipPassword)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	return attestation.Sign(ctx, predicateBytes, predicateType, repoAddr, digest, imageName, signer)
}
