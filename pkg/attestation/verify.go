package attestation

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

func Verify(ctx context.Context, repo, parentDigest, imageName, predicateType string, verifiers []signature.Verifier) ([]byte, error) {
	resolvedType, err := ResolvePredicateType(predicateType)
	if err != nil {
		return nil, err
	}

	store := artifact.NewOCIStore(repo, imageName)

	envelopeJSON, err := pullAttestationContent(ctx, store, parentDigest, imageName)
	if err != nil {
		return nil, err
	}

	stmtBytes, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, verifiers)
	if err != nil {
		return nil, fmt.Errorf("verify DSSE signature: %w", err)
	}

	predicate, foundType, err := UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	if foundType != resolvedType {
		return nil, fmt.Errorf("attestation predicate type %q does not match requested %q", foundType, resolvedType)
	}

	return []byte(predicate), nil
}
