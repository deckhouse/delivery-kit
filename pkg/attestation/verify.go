package attestation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

type PlatformVerifyStatus string

const (
	PlatformVerifyStatusVerified PlatformVerifyStatus = "verified"
	PlatformVerifyStatusMissing  PlatformVerifyStatus = "missing"
	PlatformVerifyStatusUnsigned PlatformVerifyStatus = "unsigned"
	PlatformVerifyStatusInvalid  PlatformVerifyStatus = "invalid"
)

// PlatformVerifyResult is the verification outcome for one platform manifest
// of an image index.
type PlatformVerifyResult struct {
	Platform string
	Digest   string
	Status   PlatformVerifyStatus
	Err      error
}

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

// VerifyIndex verifies the attestations of every platform manifest of the
// image index behind indexDigest and returns one result per platform. Index
// entries without a real platform (unknown/unknown) are excluded by
// artifact.ListIndexPlatforms. A non-verified platform is reported in its
// result, not as the returned error; the error is reserved for failures to
// read the index itself. When no remote options are given, per-host defaults
// from docker_registry are used.
func VerifyIndex(ctx context.Context, repo, indexDigest, imageName, predicateType string, verifiers []signature.Verifier, opts ...remote.Option) ([]PlatformVerifyResult, error) {
	resolvedType, err := ResolvePredicateType(predicateType)
	if err != nil {
		return nil, err
	}

	kindAliases, err := PredicateKindAliases(predicateType)
	if err != nil {
		return nil, err
	}

	entries, err := artifact.ListIndexPlatforms(ctx, repo, indexDigest, opts...)
	if err != nil {
		return nil, fmt.Errorf("list index platforms: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName, opts...)

	results := make([]PlatformVerifyResult, 0, len(entries))
	for _, entry := range entries {
		status, verifyErr := verifyPlatformAttestation(ctx, store, entry.Digest, resolvedType, kindAliases, verifiers)
		results = append(results, PlatformVerifyResult{
			Platform: entry.Platform,
			Digest:   entry.Digest,
			Status:   status,
			Err:      verifyErr,
		})
	}

	return results, nil
}

// VerifyIndexResultError folds per-platform verification results into a
// single verdict: nil when every platform is verified, otherwise an error
// naming each failing platform with its failure classification.
func VerifyIndexResultError(results []PlatformVerifyResult) error {
	var failures []string
	for _, result := range results {
		if result.Status == PlatformVerifyStatusVerified {
			continue
		}
		failures = append(failures, fmt.Sprintf("%s (%s): %s", result.Platform, result.Status, result.Err))
	}

	if len(failures) == 0 {
		return nil
	}

	return fmt.Errorf("attestation verification failed for %d of %d platforms:\n%s", len(failures), len(results), strings.Join(failures, "\n"))
}

func verifyPlatformAttestation(ctx context.Context, store *artifact.OCIStore, digest, resolvedType string, kindAliases []string, verifiers []signature.Verifier) (PlatformVerifyStatus, error) {
	envelopeJSON, err := PullAttestationEnvelope(ctx, store, digest, kindAliases)
	if err != nil {
		if errors.Is(err, artifact.ErrNotFound) {
			return PlatformVerifyStatusMissing, fmt.Errorf("no attestation found for digest %s: %w", digest, err)
		}
		return PlatformVerifyStatusMissing, fmt.Errorf("pull attestation for digest %s: %w", digest, err)
	}

	signed, err := HasSignatures(envelopeJSON)
	if err != nil {
		return PlatformVerifyStatusInvalid, fmt.Errorf("parse DSSE envelope: %w", err)
	}
	if !signed {
		return PlatformVerifyStatusUnsigned, errors.New("attestation present but unsigned (legacy format), rebuild with --sign-key to publish a signed attestation")
	}

	stmtBytes, err := VerifyDSSE(ctx, envelopeJSON, InTotoMediaType, verifiers)
	if err != nil {
		return PlatformVerifyStatusInvalid, fmt.Errorf("verify DSSE signature: %w", err)
	}

	_, foundType, err := UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return PlatformVerifyStatusInvalid, fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	if !PredicateTypeMatches(resolvedType, foundType) {
		return PlatformVerifyStatusInvalid, fmt.Errorf("attestation predicate type %q does not match requested %q", foundType, resolvedType)
	}

	return PlatformVerifyStatusVerified, nil
}
