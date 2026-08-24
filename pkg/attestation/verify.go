package attestation

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"
)

func Verify(ctx context.Context, repo, parentDigest, imageName, predicateType string, verifiers []signature.Verifier) ([]byte, error) {
	return pullPredicate(ctx, repo, parentDigest, imageName, predicateType, func(ctx context.Context, envelopeJSON []byte) ([]byte, error) {
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
		return stmtBytes, nil
	})
}
