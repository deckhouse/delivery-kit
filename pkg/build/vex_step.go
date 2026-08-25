package build

import (
	"context"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	vexImage "github.com/werf/werf/v2/pkg/vex/image"
)

type vexStep struct{}

func newVexStep() *vexStep {
	return &vexStep{}
}

func (step *vexStep) Converge(ctx context.Context, vexJSON []byte, stageDesc *image.StageDesc, werfImgName, targetPlatform string, signer signature.Signer, signerIdentity string) error {
	repo := stageDesc.Info.Repository
	parentDigest := stageDesc.Info.GetDigest()

	checksum := calculateVEXChecksum(vexJSON, parentDigest, signerIdentity)

	store := artifact.NewOCIStore(repo, werfImgName)

	needed, err := checkVEXPublishNeeded(ctx, store, parentDigest, checksum)
	if err != nil {
		return fmt.Errorf("check VEX publish needed: %w", err)
	}
	if !needed {
		logboek.Context(ctx).Default().LogF("image %s: VEX artifact is up to date — skipping publish\n", werfImgName)
		return nil
	}

	return logboek.Context(ctx).Default().LogProcess("image %s: Published VEX artifact", werfImgName).DoError(func() error {
		return vexImage.PushVEX(ctx, vexJSON, repo, parentDigest, werfImgName, checksum, targetPlatform, signer)
	})
}

const vexArtifactFormatVersion = "2"

// calculateVEXChecksum builds the cache identity of the VEX artifact: document
// content and parent digest (FR-011 of 013-vex-lifecycle), the bump-able artifact
// format version, and the signer public-key fingerprint — so enabling signing,
// rotating the key, or bumping the format each republish the artifact.
func calculateVEXChecksum(vexJSON []byte, parentDigest, signerIdentity string) string {
	parts := []string{
		vexArtifactFormatVersion,
		util.Sha256Hash(string(vexJSON)),
		parentDigest,
		signerIdentity,
	}
	return util.Sha256Hash(strings.Join(parts, "-"))
}

// checkVEXPublishNeeded returns true if the VEX artifact should be published
// (no existing VEX artifact of either format or its checksum annotation differs
// from the current checksum), and false if publishing can be skipped. A legacy
// annotation-less entry never matches the current checksum formula, so it always
// triggers a republish regardless of its actual kind.
func checkVEXPublishNeeded(ctx context.Context, store artifact.Store, parentDigest, checksum string) (bool, error) {
	desc, found, err := attestation.FindAttachedArtifact(ctx, store, parentDigest, attestation.PredicateKindOpenVEX)
	if err != nil {
		return false, fmt.Errorf("check VEX cache: %w", err)
	}
	if found && desc.Annotations[image.WerfChecksumAnnotation] == checksum {
		return false, nil
	}
	return true, nil
}
