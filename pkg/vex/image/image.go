package image

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
)

// PushVEX publishes a VEX document as an OCI artifact attached to the specified
// image manifest (or index) via subject reference: a signed Sigstore Bundle with
// a signer, the legacy bare-DSSE form without one. See
// attestation.PublishAttestation for the supersede semantics.
func PushVEX(ctx context.Context, vexJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string, signer signature.Signer) error {
	err := attestation.PublishAttestation(ctx, attestation.PredicateKindOpenVEX, vexJSON, repo, parentDigest, imageName, attestation.PublishAttestationOptions{
		Signer:         signer,
		Checksum:       checksum,
		TargetPlatform: targetPlatform,
	})
	if err != nil {
		return fmt.Errorf("attach VEX artifact to image %s: %w (if the registry does not support OCI subject references, use a registry that supports OCI Distribution Spec v1.1+)", imageName, err)
	}
	return nil
}
