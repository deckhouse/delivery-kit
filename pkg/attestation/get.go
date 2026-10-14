package attestation

import (
	"context"
	"errors"
	"fmt"
	"slices"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/werf/werf/v3/pkg/oci/artifact"
)

func Get(ctx context.Context, repo, parentDigest, imageName, predicateType string) ([]byte, error) {
	return pullPredicate(ctx, repo, parentDigest, imageName, predicateType, func(_ context.Context, envelopeJSON []byte) ([]byte, error) {
		stmtBytes, err := UnwrapDSSE(envelopeJSON, InTotoMediaType)
		if err != nil {
			return nil, fmt.Errorf("unwrap DSSE envelope: %w", err)
		}
		return stmtBytes, nil
	})
}

// pullPredicate resolves the attestation of the requested predicate kind and
// returns its predicate. openEnvelope turns the stored DSSE envelope into the
// in-toto statement: reading it as-is for Get, verifying its signatures for
// Verify.
//
// Each URI of the kind is tried on its own, the requested one first, and the
// first candidate the caller accepts wins. Looking the whole kind up at once
// would answer with whichever entry the registry lists first, while stopping at
// the requested URI would hide a signed attestation sitting in the neighboring
// slot from a verify. When every candidate fails, the most telling failure is
// reported — see rejectionRank.
func pullPredicate(ctx context.Context, repo, parentDigest, imageName, predicateType string, openEnvelope func(context.Context, []byte) ([]byte, error)) ([]byte, error) {
	resolvedType, err := ResolvePredicateType(predicateType)
	if err != nil {
		return nil, err
	}

	lookupTypes, err := PredicateLookupTypes(predicateType)
	if err != nil {
		return nil, err
	}

	store := artifact.NewOCIStore(repo, imageName)

	var bestErr error
	for _, lookupType := range lookupTypes {
		predicate, err := pullPredicateOfType(ctx, store, parentDigest, resolvedType, lookupType, openEnvelope)
		if err == nil {
			return predicate, nil
		}
		if rejectionRank(err) > rejectionRank(bestErr) {
			bestErr = err
		}
	}

	return nil, bestErr
}

// rejectionRank orders the ways a candidate can fail by how much it tells the
// user. The absence of an entry says the least, an entry that carries no
// signature says more, and an entry that failed verification or carries another
// predicate kind says the most — a read that tried several URIs of a kind
// reports the highest of them.
func rejectionRank(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, artifact.ErrNotFound):
		return 1
	case errors.Is(err, ErrUnsignedAttestation):
		return 2
	default:
		return 3
	}
}

func pullPredicateOfType(ctx context.Context, store *artifact.OCIStore, parentDigest, resolvedType, lookupType string, openEnvelope func(context.Context, []byte) ([]byte, error)) ([]byte, error) {
	envelopeJSON, err := PullAttestationEnvelope(ctx, store, parentDigest, []string{lookupType}, PullAttestationEnvelopeOptions{PreferUserOwned: true})
	if err != nil {
		return nil, err
	}

	stmtBytes, err := openEnvelope(ctx, envelopeJSON)
	if err != nil {
		return nil, err
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

// FindAttachedArtifact returns the descriptor of the attestation of the given
// kind stored for parentDigest, preferring the signed Sigstore Bundle over the
// legacy bare-DSSE artifact. Build steps use it to compare the stored checksum
// annotation with the one the current inputs produce.
func FindAttachedArtifact(ctx context.Context, store artifact.Store, parentDigest string, kind PredicateKind) (v1.Descriptor, bool, error) {
	for _, artifactType := range []string{BundleMediaType, DSSEMediaType} {
		desc, found, err := store.GetAttached(ctx, parentDigest, artifactType, kind.Types(), artifact.GetAttachedOptions{})
		if err != nil {
			return v1.Descriptor{}, false, fmt.Errorf("get attached %s artifact of type %q: %w", kind.Name, artifactType, err)
		}
		if found {
			return desc, true, nil
		}
	}

	return v1.Descriptor{}, false, nil
}

// PullAttestationEnvelopeOptions tunes which attestation a read answers with.
type PullAttestationEnvelopeOptions struct {
	// PreferUserOwned answers with an attestation published through attest sign when
	// one is attached, falling back to werf's own document of the same predicate
	// type. Reads of werf's own documents — sbom get, vex get — leave it unset.
	PreferUserOwned bool
}

// PullAttestationEnvelope returns the DSSE envelope of the attestation of the
// requested predicate kind: the Sigstore Bundle artifact is preferred over the
// legacy bare-DSSE one, entries annotated with a matching predicate type are
// preferred over annotation-less legacy entries, and a legacy entry is used only
// after its content proves it belongs to the requested kind.
func PullAttestationEnvelope(ctx context.Context, store *artifact.OCIStore, parentDigest string, predicateTypes []string, opts PullAttestationEnvelopeOptions) ([]byte, error) {
	if opts.PreferUserOwned {
		envelopeJSON, err := pullAttestationEnvelope(ctx, store, parentDigest, predicateTypes, artifact.GetAttachedOptions{UserOwnedOnly: true})
		if err == nil {
			return envelopeJSON, nil
		}
		if !errors.Is(err, artifact.ErrNotFound) {
			return nil, err
		}
	}

	return pullAttestationEnvelope(ctx, store, parentDigest, predicateTypes, artifact.GetAttachedOptions{})
}

func pullAttestationEnvelope(ctx context.Context, store *artifact.OCIStore, parentDigest string, predicateTypes []string, getOpts artifact.GetAttachedOptions) ([]byte, error) {
	for _, artifactType := range []string{BundleMediaType, DSSEMediaType} {
		desc, found, err := store.GetAttached(ctx, parentDigest, artifactType, predicateTypes, getOpts)
		if err != nil {
			return nil, fmt.Errorf("get attached artifact: %w", err)
		}
		if !found {
			continue
		}

		envelopeJSON, err := pullEnvelope(ctx, store, desc, artifactType)
		if err != nil {
			return nil, err
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

// pullEnvelope fetches an artifact's payload and normalizes it to a DSSE
// envelope, unwrapping the Sigstore Bundle when the artifact is one.
func pullEnvelope(ctx context.Context, store *artifact.OCIStore, desc v1.Descriptor, artifactType string) ([]byte, error) {
	content, err := store.GetContentByDigest(ctx, desc.Digest.String())
	if err != nil {
		return nil, fmt.Errorf("pull artifact content: %w", err)
	}

	if artifactType != BundleMediaType {
		return content, nil
	}

	envelopeJSON, err := UnwrapBundle(content)
	if err != nil {
		return nil, fmt.Errorf("unwrap sigstore bundle: %w", err)
	}
	return envelopeJSON, nil
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
func LegacySupersededKeys(ctx context.Context, store *artifact.OCIStore, parentDigest string, kindTypes []string) ([]artifact.Key, error) {
	var keys []artifact.Key

	for _, artifactType := range []string{BundleMediaType, DSSEMediaType} {
		desc, found, err := store.GetAttachedLegacy(ctx, parentDigest, artifactType)
		if err != nil {
			return nil, fmt.Errorf("get legacy artifact: %w", err)
		}
		if !found {
			continue
		}

		envelopeJSON, err := pullEnvelope(ctx, store, desc, artifactType)
		if err != nil {
			continue
		}

		foundType, err := StatementPredicateType(envelopeJSON)
		if err != nil {
			continue
		}

		if slices.Contains(kindTypes, foundType) {
			keys = append(keys, artifact.Key{ArtifactType: artifactType, PredicateType: ""})
		}
	}

	return keys, nil
}
