package image

import (
	"context"
	"encoding/json"

	"github.com/werf/werf/v2/pkg/attestation"
)

func WrapInDSSE(payload []byte, payloadType string) ([]byte, error) {
	return attestation.WrapInDSSE(context.Background(), payload, payloadType, nil)
}

func UnwrapDSSE(envelopeJSON []byte, expectedPayloadType string) ([]byte, error) {
	return attestation.UnwrapDSSE(envelopeJSON, expectedPayloadType)
}

func WrapInInTotoStatement(predicate []byte, predicateType, repo, digestHex string) ([]byte, error) {
	return attestation.WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
}

func UnwrapInTotoStatement(statementJSON []byte) (json.RawMessage, string, error) {
	return attestation.UnwrapInTotoStatement(statementJSON)
}
