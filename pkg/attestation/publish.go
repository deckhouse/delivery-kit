package attestation

import (
	"context"
	"fmt"

	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v2/pkg/oci/artifact"
)

type PublishAttestationOptions struct {
	// Signer signs the DSSE envelope; nil publishes the legacy unsigned form.
	Signer         signature.Signer
	Checksum       string
	TargetPlatform string
}

// PublishAttestation publishes a predicate document of the given kind as an OCI
// artifact attached to parentDigest. With a signer the artifact is a Sigstore
// Bundle carrying the kind's signed predicate; without one it is a bare DSSE
// envelope with the legacy predicate. Publishing supersedes the artifact of the
// opposite signing state (per the kind's downgrade policy) and any legacy
// annotation-less entry whose content proves it belongs to this kind, so exactly
// one artifact of the kind per image remains behind.
func PublishAttestation(ctx context.Context, kind PredicateKind, predicate []byte, repo, parentDigest, imageName string, opts PublishAttestationOptions) error {
	digestHex, err := artifact.DigestHex(parentDigest)
	if err != nil {
		return fmt.Errorf("extract digest hex: %w", err)
	}

	predicateType := kind.UnsignedType
	if opts.Signer != nil {
		predicateType = kind.SignedType
	}

	stmtBytes, err := WrapInInTotoStatement(predicate, predicateType, repo, digestHex)
	if err != nil {
		return fmt.Errorf("wrap %s predicate in in-toto statement: %w", kind.Name, err)
	}

	envelopeBytes, err := WrapInDSSE(ctx, stmtBytes, InTotoMediaType, opts.Signer)
	if err != nil {
		return fmt.Errorf("wrap in-toto statement in DSSE: %w", err)
	}

	store := artifact.NewOCIStore(repo, imageName)

	superseded, err := LegacySupersededKeys(ctx, store, parentDigest, kind.Types())
	if err != nil {
		return fmt.Errorf("resolve legacy %s entries: %w", kind.Name, err)
	}

	if opts.Signer != nil {
		signed, err := HasSignatures(envelopeBytes)
		if err != nil {
			return fmt.Errorf("check DSSE signatures: %w", err)
		}
		if !signed {
			return fmt.Errorf("%s dsse envelope has no signatures after signing", kind.Name)
		}

		pubKey, err := opts.Signer.PublicKey()
		if err != nil {
			return fmt.Errorf("get signer public key: %w", err)
		}

		bundleBytes, err := WrapInBundle(envelopeBytes, pubKey)
		if err != nil {
			return fmt.Errorf("wrap dsse in sigstore bundle: %w", err)
		}

		superseded = append(superseded, kindSlotKeys(DSSEMediaType, kind)...)
		return store.AttachSuperseding(ctx, parentDigest, BundleMediaType, bundleBytes, opts.Checksum, opts.TargetPlatform, predicateType, superseded)
	}

	if kind.DowngradeSupersede {
		superseded = append(superseded, kindSlotKeys(BundleMediaType, kind)...)
	}
	return store.AttachSuperseding(ctx, parentDigest, DSSEMediaType, envelopeBytes, opts.Checksum, opts.TargetPlatform, predicateType, superseded)
}

func kindSlotKeys(artifactType string, kind PredicateKind) []artifact.Key {
	keys := make([]artifact.Key, 0, len(kind.Types()))
	for _, predicateType := range kind.Types() {
		keys = append(keys, artifact.Key{ArtifactType: artifactType, PredicateType: predicateType})
	}
	return keys
}
