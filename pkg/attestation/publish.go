package attestation

import (
	"context"
	"fmt"
	"slices"

	"github.com/samber/lo"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/werf/werf/v3/pkg/oci/artifact"
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
// opposite signing state and any legacy annotation-less entry whose content
// proves it belongs to this kind, so exactly one artifact of the kind per image
// remains behind and a read never prefers the previous signing state.
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

	superseded = append(superseded, kindSlotKeys(BundleMediaType, kind)...)
	return store.AttachSuperseding(ctx, parentDigest, DSSEMediaType, envelopeBytes, opts.Checksum, opts.TargetPlatform, predicateType, superseded)
}

var _ artifact.SupersedeRule = CopySupersededKeys

// CopySupersededKeys reports the destination slots an attestation being copied
// replaces: the slots of the opposite signing state of its own kind, limited to
// those the source no longer holds. Propagation then mirrors the slot state of
// the source repository instead of accumulating both signing states, so a reader
// of the destination never prefers an artifact of the previous one. Artifacts of
// an unknown kind and legacy annotation-less ones replace nothing.
func CopySupersededKeys(copied artifact.Key, srcSlots []artifact.Key) []artifact.Key {
	kind, ok := predicateKindOf(copied.PredicateType)
	if !ok {
		return nil
	}

	oppositeType := map[string]string{
		BundleMediaType: DSSEMediaType,
		DSSEMediaType:   BundleMediaType,
	}[copied.ArtifactType]
	if oppositeType == "" {
		return nil
	}

	return lo.Filter(kindSlotKeys(oppositeType, kind), func(key artifact.Key, _ int) bool {
		return !slices.Contains(srcSlots, key)
	})
}

func kindSlotKeys(artifactType string, kind PredicateKind) []artifact.Key {
	keys := make([]artifact.Key, 0, len(kind.Types()))
	for _, predicateType := range kind.Types() {
		keys = append(keys, artifact.Key{ArtifactType: artifactType, PredicateType: predicateType})
	}
	return keys
}
