package image

import (
	"context"
	"fmt"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
)

// PushVEX publishes a VEX document as an OCI artifact attached to the
// specified image manifest via subject reference.
//
// Parameters:
//   - ctx: context for cancellation and deadlines
//   - vexJSON: the raw VEX document JSON bytes
//   - repo: the OCI repository (e.g., "registry.example.com/my-project")
//   - parentDigest: the digest of the parent image manifest (e.g., "sha256:abcd...")
//   - imageName: the image name from werf.yaml
//   - checksum: checksum for cache invalidation (e.g., SHA-256 of VEX file)
//   - targetPlatform: target platform string (e.g., "linux/amd64")
func PushVEX(ctx context.Context, vexJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string) error {
	digestHex, err := artifact.DigestHex(parentDigest)
	if err != nil {
		return fmt.Errorf("extract digest hex: %w", err)
	}

	stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, vex.VEXPredicateURI, repo, digestHex)
	if err != nil {
		return fmt.Errorf("wrap VEX in in-toto statement: %w", err)
	}

	envelopeBytes, err := attestation.WrapInDSSE(ctx, stmtBytes, vex.InTotoMediaType, nil)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName)
	if err := store.Attach(ctx, parentDigest, vex.DSSEMediaType, envelopeBytes, checksum, targetPlatform); err != nil {
		return fmt.Errorf("attach VEX artifact to image %s: %w (if the registry does not support OCI subject references, use a registry that supports OCI Distribution Spec v1.1+)", imageName, err)
	}

	return nil
}
