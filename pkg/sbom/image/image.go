package image

import (
	"context"
	"fmt"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/distribution/reference"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

const scratchImageName = "scratch"

// Predicate URIs of SBOM artifacts. attestation.PredicateKindCycloneDX owns them;
// these aliases exist so SBOM code reads in its own terms.
var (
	// CycloneDX16Predicate is the predicate type of unsigned SBOM artifacts.
	CycloneDX16Predicate = attestation.PredicateKindCycloneDX.UnsignedType

	// CycloneDXPredicate is the predicate type of signed SBOM attestations
	// (unversioned, per the cosign convention).
	CycloneDXPredicate = attestation.PredicateKindCycloneDX.SignedType

	// CycloneDXPredicateTypes lists every predicate URI denoting the CycloneDX SBOM
	// attestation kind.
	CycloneDXPredicateTypes = attestation.PredicateKindCycloneDX.Types()
)

func IsScratchRef(imageRef string) bool {
	if imageRef == "" {
		return false
	}
	if imageRef == scratchImageName {
		return true
	}
	ref, err := reference.ParseAnyReference(imageRef)
	if err != nil {
		return false
	}
	named, ok := ref.(reference.Named)
	if !ok {
		return false
	}
	path := reference.Path(named)
	return path == scratchImageName || strings.HasSuffix(path, "/"+scratchImageName)
}

func FallbackTag(parentDigest string) string {
	return artifact.FallbackTag(parentDigest)
}

func PushSBOM(ctx context.Context, bomJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string, signer signature.Signer) error {
	return attestation.PublishAttestation(ctx, attestation.PredicateKindCycloneDX, bomJSON, repo, parentDigest, imageName, attestation.PublishAttestationOptions{
		Signer:         signer,
		Checksum:       checksum,
		TargetPlatform: targetPlatform,
	})
}

func PullSBOM(ctx context.Context, repo, parentDigest, imageName string) ([]byte, error) {
	store := artifact.NewOCIStore(repo, imageName)

	envelopeJSON, err := attestation.PullAttestationEnvelope(ctx, store, parentDigest, CycloneDXPredicateTypes)
	if err != nil {
		return nil, err
	}

	return extractBOMFromEnvelope(envelopeJSON)
}

func extractBOMFromEnvelope(envelopeJSON []byte) ([]byte, error) {
	stmtBytes, err := UnwrapDSSE(envelopeJSON, attestation.InTotoMediaType)
	if err != nil {
		return nil, fmt.Errorf("unwrap DSSE envelope: %w", err)
	}

	predicate, predicateType, err := UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	if !slices.Contains(CycloneDXPredicateTypes, predicateType) {
		return nil, fmt.Errorf("unexpected in-toto predicate type %q, expected one of %s", predicateType, strings.Join(CycloneDXPredicateTypes, ", "))
	}

	return []byte(predicate), nil
}

func PullCycloneDX16BOM(ctx context.Context, repo, parentDigest, imageName string) (*cdx.BOM, error) {
	bomJSON, err := PullSBOM(ctx, repo, parentDigest, imageName)
	if err != nil {
		return nil, err
	}

	bom, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(bomJSON)
	if err != nil {
		return nil, fmt.Errorf("parse CycloneDX BOM: %w", err)
	}

	return bom, nil
}

func PullCycloneDX16BOMContent(ctx context.Context, envelopeJSON []byte) ([]byte, error) {
	return extractBOMFromEnvelope(envelopeJSON)
}
