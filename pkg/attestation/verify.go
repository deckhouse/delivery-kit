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

	kindAliases, err := PredicateKindAliases(predicateType)
	if err != nil {
		return nil, err
	}

	store := artifact.NewOCIStore(repo, imageName)

	envelopeJSON, err := PullAttestationEnvelope(ctx, store, parentDigest, kindAliases)
	if err != nil {
		return nil, err
	}

	signed, err := HasSignatures(envelopeJSON)
	if err != nil {
		return nil, fmt.Errorf("check DSSE signatures: %w", err)
	}
	if !signed {
		return nil, fmt.Errorf("attestation for digest %s is present but unsigned (legacy format): rebuild with --sign-key to publish a signed attestation", parentDigest)
	}

	stmtBytes, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, verifiers)
	if err != nil {
		return nil, fmt.Errorf("verify DSSE signature: %w", err)
	}

	predicate, foundType, err := UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	if !PredicateTypeMatches(resolvedType, foundType) {
		return nil, fmt.Errorf("attestation predicate type %q does not match requested %q", foundType, resolvedType)
	}

	return []byte(predicate), nil
}
