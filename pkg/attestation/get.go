package attestation

import (
	"context"
	"fmt"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

func Get(ctx context.Context, repo, parentDigest, imageName, predicateType string) ([]byte, error) {
	resolvedType, err := ResolvePredicateType(predicateType)
	if err != nil {
		return nil, err
	}

	store := artifact.NewOCIStore(repo, imageName)

	envelopeJSON, err := pullAttestationContent(ctx, store, parentDigest, imageName)
	if err != nil {
		return nil, err
	}

	stmtBytes, err := UnwrapDSSE(envelopeJSON, InTotoMediaType)
	if err != nil {
		return nil, fmt.Errorf("unwrap DSSE envelope: %w", err)
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

func pullAttestationContent(ctx context.Context, store *artifact.OCIStore, parentDigest, imageName string) ([]byte, error) {
	getContent := store.GetAttachedContent
	if imageName == "" {
		getContent = store.GetAttachedContentAny
	}

	content, err := getContent(ctx, parentDigest, BundleMediaType)
	if err == nil {
		envelopeJSON, unwrapErr := UnwrapBundle(content)
		if unwrapErr != nil {
			return nil, fmt.Errorf("unwrap sigstore bundle: %w", unwrapErr)
		}
		return envelopeJSON, nil
	}

	return getContent(ctx, parentDigest, DSSEMediaType)
}
