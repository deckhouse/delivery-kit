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

func PushSBOM(ctx context.Context, bomJSON []byte, repo, parentDigest, imageName, checksum, targetPlatform string, signer signature.Signer) error {
	digestHex, err := artifact.DigestHex(parentDigest)
	if err != nil {
		return fmt.Errorf("extract digest hex: %w", err)
	}

	predicateType := CycloneDX16Predicate
	if signer != nil {
		predicateType = CycloneDXPredicate
	}

	stmtBytes, err := WrapInInTotoStatement(bomJSON, predicateType, repo, digestHex)
	if err != nil {
		return fmt.Errorf("wrap BOM in in-toto statement: %w", err)
	}

	envelopeBytes, err := WrapInDSSE(ctx, stmtBytes, attestation.InTotoMediaType, signer)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	if signer != nil {
		signed, err := attestation.HasSignatures(envelopeBytes)
		if err != nil {
			return fmt.Errorf("check DSSE signatures: %w", err)
		}
		if !signed {
			return fmt.Errorf("sbom dsse envelope has no signatures after signing")
		}

		pubKey, err := signer.PublicKey()
		if err != nil {
			return fmt.Errorf("get signer public key: %w", err)
		}

		bundleBytes, err := attestation.WrapInBundle(envelopeBytes, pubKey)
		if err != nil {
			return fmt.Errorf("wrap dsse in sigstore bundle: %w", err)
		}

		store := artifact.NewOCIStore(repo, imageName)
		return store.AttachSuperseding(ctx, parentDigest, attestation.BundleMediaType, bundleBytes, checksum, targetPlatform, []string{attestation.DSSEMediaType})
	}

	store := artifact.NewOCIStore(repo, imageName)
	return store.Attach(ctx, parentDigest, attestation.DSSEMediaType, envelopeBytes, checksum, targetPlatform)
}

func PullSBOM(ctx context.Context, repo, parentDigest, imageName string) ([]byte, error) {
	store := artifact.NewOCIStore(repo, imageName)

	envelopeJSON, err := pullSBOMArtifact(ctx, store, parentDigest, imageName)
	if err != nil {
		return nil, err
	}

	return extractBOMFromEnvelope(envelopeJSON)
}

func pullSBOMArtifact(ctx context.Context, store *artifact.OCIStore, parentDigest, imageName string) ([]byte, error) {
	getContent := store.GetAttachedContent
	if imageName == "" {
		getContent = store.GetAttachedContentAny
	}

	content, err := getContent(ctx, parentDigest, attestation.BundleMediaType)
	if err == nil {
		envelopeJSON, unwrapErr := attestation.UnwrapBundle(content)
		if unwrapErr != nil {
			return nil, fmt.Errorf("unwrap sigstore bundle: %w", unwrapErr)
		}
		return envelopeJSON, nil
	}

	content, err = getContent(ctx, parentDigest, attestation.DSSEMediaType)
	if err != nil {
		return nil, fmt.Errorf("get attached SBOM: %w", err)
	}

	return content, nil
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
