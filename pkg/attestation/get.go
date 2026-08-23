package attestation

import (
	"context"
	"fmt"
	"slices"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

func Get(ctx context.Context, repo, parentDigest, imageName, predicateType string) ([]byte, error) {
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

	stmtBytes, err := UnwrapDSSE(envelopeJSON, InTotoMediaType)
	if err != nil {
		return nil, fmt.Errorf("unwrap DSSE envelope: %w", err)
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

// PullAttestationEnvelope returns the DSSE envelope of the attestation of the
// requested predicate kind: the Sigstore Bundle artifact is preferred over the
// legacy bare-DSSE one, entries annotated with a matching predicate type are
// preferred over annotation-less legacy entries, and a legacy entry is used only
// after its content proves it belongs to the requested kind.
func PullAttestationEnvelope(ctx context.Context, store *artifact.OCIStore, parentDigest string, predicateTypes []string) ([]byte, error) {
	for _, artifactType := range []string{BundleMediaType, DSSEMediaType} {
		desc, found, err := store.GetAttached(ctx, parentDigest, artifactType, predicateTypes)
		if err != nil {
			return nil, fmt.Errorf("get attached artifact: %w", err)
		}
		if !found {
			continue
		}

		content, err := store.GetContentByDigest(ctx, desc.Digest.String())
		if err != nil {
			return nil, fmt.Errorf("pull artifact content: %w", err)
		}

		envelopeJSON := content
		if artifactType == BundleMediaType {
			envelopeJSON, err = UnwrapBundle(content)
			if err != nil {
				return nil, fmt.Errorf("unwrap sigstore bundle: %w", err)
			}
		}

		if len(predicateTypes) > 0 && desc.Annotations[artifact.PredicateTypeAnnotation] == "" {
			foundType, err := StatementPredicateType(envelopeJSON)
			if err != nil || !slices.Contains(predicateTypes, foundType) {
				continue
			}
		}

		return envelopeJSON, nil
	}

	return nil, fmt.Errorf("no attestation of the requested predicate type found for digest %q: %w", parentDigest, artifact.ErrNotFound)
}

// ResolveAttestationDigest resolves a reference digest to the digest carrying
// attestations of the given predicate kind. Image-level kinds (OpenVEX) use an
// index reference as-is and reject --platform on it; every other kind resolves a
// multi-platform index to the requested platform manifest.
func ResolveAttestationDigest(ctx context.Context, repo, digest, platform, predicateType string) (string, error) {
	if !ImageLevelPredicateType(predicateType) {
		return artifact.ResolvePlatformDigest(ctx, repo, digest, platform)
	}

	isIndex, err := artifact.IsIndexReference(ctx, repo, digest)
	if err != nil {
		return "", err
	}
	if !isIndex {
		return artifact.ResolvePlatformDigest(ctx, repo, digest, platform)
	}
	if platform != "" {
		return "", fmt.Errorf("OpenVEX attestations are image-level and attached to the image index; --platform is not applicable")
	}
	return digest, nil
}

// StatementPredicateType extracts the in-toto statement predicate type from a DSSE
// envelope. Used to establish the kind of legacy artifacts published before
// predicate-type annotations existed.
func StatementPredicateType(envelopeJSON []byte) (string, error) {
	stmtBytes, err := UnwrapDSSE(envelopeJSON, InTotoMediaType)
	if err != nil {
		return "", fmt.Errorf("unwrap DSSE envelope: %w", err)
	}

	_, predicateType, err := UnwrapInTotoStatement(stmtBytes)
	if err != nil {
		return "", fmt.Errorf("unwrap in-toto statement: %w", err)
	}

	return predicateType, nil
}

// LegacySupersededKeys returns superseded slot keys for annotation-less legacy
// entries attached to parentDigest whose content proves they belong to the given
// predicate kind. Legacy entries of other kinds (or unreadable ones) are left in
// place: an artifact must never be evicted by a writer of a different kind.
func LegacySupersededKeys(ctx context.Context, store *artifact.OCIStore, parentDigest string, kindAliases []string) ([]artifact.Key, error) {
	var keys []artifact.Key

	for _, artifactType := range []string{BundleMediaType, DSSEMediaType} {
		desc, found, err := store.GetAttachedLegacy(ctx, parentDigest, artifactType)
		if err != nil {
			return nil, fmt.Errorf("get legacy artifact: %w", err)
		}
		if !found {
			continue
		}

		content, err := store.GetContentByDigest(ctx, desc.Digest.String())
		if err != nil {
			continue
		}

		envelopeJSON := content
		if artifactType == BundleMediaType {
			envelopeJSON, err = UnwrapBundle(content)
			if err != nil {
				continue
			}
		}

		foundType, err := StatementPredicateType(envelopeJSON)
		if err != nil {
			continue
		}

		if slices.Contains(kindAliases, foundType) {
			keys = append(keys, artifact.Key{ArtifactType: artifactType, PredicateType: ""})
		}
	}

	return keys, nil
}
