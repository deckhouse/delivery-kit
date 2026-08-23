package image

import (
	"context"
	"fmt"

	"github.com/samber/lo"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/vex"
)

// PushVEX publishes a VEX document as an OCI artifact attached to the
// specified image manifest (or index) via subject reference.
//
// With a signer the document is published as a signed Sigstore Bundle with the
// unversioned OpenVEX predicate; without one it keeps the legacy bare-DSSE form
// with the versioned predicate. Publishing supersedes the artifact of the
// opposite signing state and any legacy entry whose content proves it is a VEX,
// so exactly one VEX artifact per image remains behind.
//
// Parameters:
//   - ctx: context for cancellation and deadlines
//   - vexJSON: the raw VEX document JSON bytes
//   - repo: the OCI repository (e.g., "registry.example.com/my-project")
//   - parentDigest: the digest of the parent image manifest or index (e.g., "sha256:abcd...")
//   - imageName: the image name from werf.yaml
//   - checksum: checksum for cache invalidation
//   - targetPlatform: target platform string (e.g., "linux/amd64")
//   - signer: DSSE signer; nil publishes the legacy unsigned form
func PushVEX(ctx context.Context, vexJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string, signer signature.Signer) error {
	digestHex, err := artifact.DigestHex(parentDigest)
	if err != nil {
		return fmt.Errorf("extract digest hex: %w", err)
	}

	predicateType := vex.VEXPredicateURI
	if signer != nil {
		predicateType = vex.VEXPredicateURIUnversioned
	}

	stmtBytes, err := attestation.WrapInInTotoStatement(vexJSON, predicateType, repo, digestHex)
	if err != nil {
		return fmt.Errorf("wrap VEX in in-toto statement: %w", err)
	}

	envelopeBytes, err := attestation.WrapInDSSE(ctx, stmtBytes, vex.InTotoMediaType, signer)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName)

	superseded, err := attestation.LegacySupersededKeys(ctx, store, parentDigest, vex.VEXPredicateTypes)
	if err != nil {
		return fmt.Errorf("resolve legacy VEX entries: %w", err)
	}

	if signer != nil {
		signed, err := attestation.HasSignatures(envelopeBytes)
		if err != nil {
			return fmt.Errorf("check DSSE signatures: %w", err)
		}
		if !signed {
			return fmt.Errorf("vex dsse envelope has no signatures after signing")
		}

		pubKey, err := signer.PublicKey()
		if err != nil {
			return fmt.Errorf("get signer public key: %w", err)
		}

		bundleBytes, err := attestation.WrapInBundle(envelopeBytes, pubKey)
		if err != nil {
			return fmt.Errorf("wrap dsse in sigstore bundle: %w", err)
		}

		superseded = append(superseded, vexKindKeys(vex.DSSEMediaType)...)
		if err := store.AttachSuperseding(ctx, parentDigest, attestation.BundleMediaType, bundleBytes, checksum, targetPlatform, predicateType, superseded); err != nil {
			return fmt.Errorf("attach signed VEX artifact to image %s: %w (if the registry does not support OCI subject references, use a registry that supports OCI Distribution Spec v1.1+)", imageName, err)
		}
		return nil
	}

	superseded = append(superseded, vexKindKeys(attestation.BundleMediaType)...)
	if err := store.AttachSuperseding(ctx, parentDigest, vex.DSSEMediaType, envelopeBytes, checksum, targetPlatform, predicateType, superseded); err != nil {
		return fmt.Errorf("attach VEX artifact to image %s: %w (if the registry does not support OCI subject references, use a registry that supports OCI Distribution Spec v1.1+)", imageName, err)
	}
	return nil
}

func vexKindKeys(artifactType string) []artifact.Key {
	return lo.Map(vex.VEXPredicateTypes, func(predicateType string, _ int) artifact.Key {
		return artifact.Key{ArtifactType: artifactType, PredicateType: predicateType}
	})
}
