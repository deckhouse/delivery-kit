package image

import (
	"context"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/distribution/reference"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/oci/artifact"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
)

const (
	scratchImageName     = "scratch"
	CycloneDX16Predicate = "https://cyclonedx.org/bom/v1.6"
	CycloneDXPredicate   = "https://cyclonedx.org/bom"
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

// CycloneDXPredicateTypes lists every predicate URI denoting the CycloneDX SBOM
// attestation kind.
var CycloneDXPredicateTypes = attestation.PredicateKindCycloneDX.Types()

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

	if predicateType != CycloneDX16Predicate && predicateType != CycloneDXPredicate {
		return nil, fmt.Errorf("unexpected in-toto predicate type %q, expected %q or %q", predicateType, CycloneDX16Predicate, CycloneDXPredicate)
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
