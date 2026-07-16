package attestation

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/werf/werf/v2/pkg/docker_registry"
	"github.com/werf/werf/v2/pkg/oci/artifact"
)

type AttestationInfo struct {
	PredicateType string
	Digest        string
	Signed        bool
}

func List(ctx context.Context, repo, parentDigest string) ([]AttestationInfo, error) {
	opts := append([]remote.Option{remote.WithContext(ctx)}, docker_registry.API().RemoteOptionsForHost(ctx, repo)...)

	idx, err := artifact.PullFallbackIndex(ctx, repo, parentDigest, opts...)
	if err != nil {
		return nil, fmt.Errorf("pull fallback index: %w", err)
	}

	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read fallback index manifest: %w", err)
	}

	store := artifact.NewOCIStore(repo, "")

	var result []AttestationInfo
	for _, desc := range im.Manifests {
		if desc.ArtifactType != DSSEMediaType {
			continue
		}

		info := AttestationInfo{
			Digest: desc.Digest.String(),
		}

		content, err := store.GetAttachedContentAny(ctx, parentDigest, DSSEMediaType)
		if err != nil {
			result = append(result, info)
			continue
		}

		signed, err := HasSignatures(content)
		if err != nil {
			return nil, fmt.Errorf("check signatures for %s: %w", desc.Digest.String(), err)
		}
		info.Signed = signed

		if stmtBytes, err := UnwrapDSSE(content, InTotoMediaType); err == nil {
			if _, predicateType, err := UnwrapInTotoStatement(stmtBytes); err == nil {
				info.PredicateType = predicateType
			}
		}

		result = append(result, info)
	}

	return result, nil
}
