package image

import (
	"context"
	"fmt"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
)

// DSSEMediaType is the media type for DSSE envelopes containing VEX attestations.
const DSSEMediaType = "application/vnd.dsse.envelope.v1+json"

// InTotoMediaType is the media type for in-toto statements containing VEX predicates.
const InTotoMediaType = "application/vnd.in-toto+json"

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

	envelopeBytes, err := attestation.WrapInDSSE(ctx, stmtBytes, InTotoMediaType, nil)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName)
	return store.Attach(ctx, parentDigest, DSSEMediaType, envelopeBytes, checksum, targetPlatform)
}

// PullVEX retrieves a VEX document OCI artifact attached to the
// specified image manifest.
//
// Parameters:
//   - ctx: context for cancellation and deadlines
//   - repo: the OCI repository (e.g., "registry.example.com/my-project")
//   - parentDigest: the digest of the parent image manifest (e.g., "sha256:abcd...")
//   - imageName: the image name from werf.yaml
//
// Returns the raw VEX document JSON bytes.
func PullVEX(ctx context.Context, repo, parentDigest, imageName string) ([]byte, error) {
	store := artifact.NewOCIStore(repo, imageName)

	var envelopeJSON []byte
	if imageName != "" {
		var err error
		envelopeJSON, err = store.GetAttachedContent(ctx, parentDigest, DSSEMediaType)
		if err != nil {
			return nil, fmt.Errorf("get attached VEX: %w", err)
		}
	} else {
		var err error
		envelopeJSON, err = store.GetAttachedContentAny(ctx, parentDigest, DSSEMediaType)
		if err != nil {
			return nil, fmt.Errorf("get attached VEX: %w", err)
		}
	}

	stmtBytes, err := attestation.UnwrapDSSE(envelopeJSON, InTotoMediaType)
	if err != nil {
		return nil, fmt.Errorf("unwrap DSSE envelope: %w", err)
	}

	predicate, predicateType, err := attestation.UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	if predicateType != vex.VEXPredicateURI {
		return nil, fmt.Errorf("unexpected in-toto predicate type %q, expected %q", predicateType, vex.VEXPredicateURI)
	}

	return []byte(predicate), nil
}

// FallbackTag returns the fallback tag for a given parent digest.
func FallbackTag(parentDigest string) string {
	return artifact.FallbackTag(parentDigest)
}
