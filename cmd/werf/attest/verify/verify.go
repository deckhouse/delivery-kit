package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/sigstore/sigstore/pkg/signature"
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

	var typeFlag string
	var digestFlag string
	var tagFlag string
	var keyFlags []string
	var imageFlag string
	var platformFlag string

	cmd := common.SetCommandContext(ctx, &cobra.Command{
		Use:                   "verify",
		Short:                 "Verify a signed attestation attached to an image",
		Long:                  common.GetLongCommandDescription(GetDocs().Long),
		DisableFlagsInUseLine: true,
		Hidden:                true,
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

			if typeFlag == "" {
				return fmt.Errorf("--type is required")
			}
			if len(keyFlags) == 0 {
				return fmt.Errorf("at least one --key is required")
			}

			common.LogVersion()

			return common.LogRunningTime(func() error {
				return runVerify(ctx, typeFlag, digestFlag, tagFlag, keyFlags, imageFlag, platformFlag)
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

	cmd.Flags().StringVarP(&typeFlag, "type", "", "", fmt.Sprintf("Predicate type: %s, or a full URI (required)", attestation.PredicateTypeHelp()))
	cmd.Flags().StringVarP(&digestFlag, "digest", "", "", "Digest of the image (e.g. sha256:abc123)")
	cmd.Flags().StringVarP(&tagFlag, "tag", "", "", "Tag of the image (resolved to digest)")
	cmd.Flags().StringArrayVarP(&keyFlags, "key", "", nil, "Path to public key PEM file for verification (repeatable, any match = success)")
	cmd.Flags().StringVarP(&imageFlag, "image", "", "", "Image name for artifact lookup")
	cmd.Flags().StringVarP(&platformFlag, "platform", "", "", "Platform to verify when the reference is a multi-platform index, format: OS/ARCH[/VARIANT]. When omitted for an index, attestations of all its platforms are verified")

	return cmd
}

func runVerify(ctx context.Context, predicateType, digest, tag string, keyPaths []string, imageName, platform string) error {
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

	verifiers, err := attestation.LoadVerifiers(keyPaths)
	if err != nil {
		return fmt.Errorf("load verification keys: %w", err)
	}

	if platform == "" {
		entries, err := artifact.ListIndexPlatforms(ctx, repoAddr, digest)
		if err != nil {
			return err
		}
		if isIndex := len(entries) != 1 || entries[0].Platform != ""; isIndex {
			return runVerifyIndex(ctx, repoAddr, digest, imageName, predicateType, verifiers)
		}
	} else {
		digest, err = artifact.ResolvePlatformDigest(ctx, repoAddr, digest, platform)
		if err != nil {
			return err
		}
	}

	predicateBytes, err := attestation.Verify(ctx, repoAddr, digest, imageName, predicateType, verifiers)
	if err != nil {
		return err
	}

	return logboek.Streams().DoErrorWithoutProxyStreamDataFormatting(func() error {
		if _, err := io.Copy(os.Stdout, bytes.NewReader(predicateBytes)); err != nil {
			return fmt.Errorf("write verified attestation to stdout: %w", err)
		}
		return nil
	})
}

func runVerifyIndex(ctx context.Context, repoAddr, indexDigest, imageName, predicateType string, verifiers []signature.Verifier) error {
	results, err := attestation.VerifyIndex(ctx, repoAddr, indexDigest, imageName, predicateType, verifiers)
	if err != nil {
		return err
	}

	if err := logboek.Streams().DoErrorWithoutProxyStreamDataFormatting(func() error {
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "PLATFORM\tDIGEST\tSTATUS")
		for _, result := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", result.Platform, result.Digest, result.Status)
		}
		return w.Flush()
	}); err != nil {
		return err
	}

	return attestation.VerifyIndexResultError(results)
}
