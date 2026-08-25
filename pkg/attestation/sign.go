package attestation

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

func Sign(ctx context.Context, predicate []byte, predicateType, repo, parentDigest, imageName string, signer signature.Signer) error {
	resolvedType, err := ResolvePredicateType(predicateType)
	if err != nil {
		return err
	}

	digestHex, err := artifact.DigestHex(parentDigest)
	if err != nil {
		return fmt.Errorf("extract digest hex: %w", err)
	}

	stmtBytes, err := WrapInInTotoStatement(predicate, resolvedType, repo, digestHex)
	if err != nil {
		return fmt.Errorf("wrap predicate in in-toto statement: %w", err)
	}

	envelopeBytes, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, signer)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName)
	return store.Attach(ctx, parentDigest, DSSEMediaType, envelopeBytes, "", "", resolvedType)
}
