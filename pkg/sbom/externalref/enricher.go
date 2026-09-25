package externalref

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

// validateRefKind restricts enrichment to the reference types the ISPRAS SBOM
// schema accepts: a component must carry a vcs or a source-distribution link.
// Any other type would pass the build and fail validation afterwards.
func validateRefKind(kind string) error {
	switch cdx.ExternalReferenceType(kind) {
	case cdx.ERTypeVCS, cdx.ERTypeSourceDistribution:
		return nil
	default:
		return fmt.Errorf("enrich: external reference kind %q is not allowed, expected %q or %q", kind, cdx.ERTypeVCS, cdx.ERTypeSourceDistribution)
	}
}

// The ISPRAS SBOM schema identifies a source distribution by a GOST R 34.11-2012
// (Streebog) digest of the archive the link points to and accepts no other
// algorithm there, so a source-distribution reference without one fails
// validation after an otherwise green build. The resolver computes the digest;
// enrichment only checks its shape before it enters the SBOM.
const (
	hashAlgStreebog256 = "STREEBOG-256"
	hashAlgStreebog512 = "STREEBOG-512"
)

var hashContentRe = map[string]*regexp.Regexp{
	hashAlgStreebog256: regexp.MustCompile(`^[a-fA-F0-9]{64}$`),
	hashAlgStreebog512: regexp.MustCompile(`^[a-fA-F0-9]{128}$`),
}

// validateRefHashes rejects a source distribution the SBOM could not be
// validated with: no digest at all, or a digest in an algorithm or an encoding
// the schema does not accept.
func validateRefHashes(kind string, hashes []Hash) error {
	if cdx.ExternalReferenceType(kind) != cdx.ERTypeSourceDistribution {
		return nil
	}

	if len(hashes) == 0 {
		return fmt.Errorf("enrich: source distribution has no hashes, expected %q or %q", hashAlgStreebog256, hashAlgStreebog512)
	}

	for _, hash := range hashes {
		contentRe, ok := hashContentRe[hash.Algorithm]
		if !ok {
			return fmt.Errorf("enrich: source distribution hash algorithm %q is not allowed, expected %q or %q", hash.Algorithm, hashAlgStreebog256, hashAlgStreebog512)
		}
		if !contentRe.MatchString(hash.Content) {
			return fmt.Errorf("enrich: source distribution hash %q has invalid content %q, expected %s", hash.Algorithm, hash.Content, hashContentDescription(hash.Algorithm))
		}
	}

	return nil
}

func purlNotExpected(ct cdx.ComponentType) bool {
	switch ct {
	case cdx.ComponentTypeOS,
		cdx.ComponentTypeDevice,
		cdx.ComponentTypeDeviceDriver,
		cdx.ComponentTypeFile,
		cdx.ComponentTypeFirmware,
		cdx.ComponentTypePlatform,
		cdx.ComponentTypeData,
		cdx.ComponentTypeMachineLearningModel,
		cdx.ComponentTypeCryptographicAsset:
		return true
	default:
		return false
	}
}

type Enricher struct {
	Resolve func(ctx context.Context, purl string) (*ResolveResult, error)
}

func NewEnricher(resolve func(ctx context.Context, purl string) (*ResolveResult, error)) *Enricher {
	return &Enricher{Resolve: resolve}
}

type componentError struct {
	name string
	purl string
	err  error
}

// ComponentError carries per-component failure details for enrichment.
// The details field contains the formatted component failure lines
// (e.g., "- apk-tools (pkg:apk/...): empty url\n") without any header prefix.
// Use ComponentDetails() to extract them without text parsing.
type ComponentError struct {
	err     error  // private: joined component errors
	details string // private: "- name (purl): err\n- ..."
}

func (e *ComponentError) Error() string {
	return fmt.Sprintf("resolve external references: components failed:\n%s", e.details)
}

func (e *ComponentError) Unwrap() error {
	return e.err
}

// ComponentDetails returns only the per-component failure lines
// without any header, ready for build-level aggregation.
func (e *ComponentError) ComponentDetails() string {
	return e.details
}

func (e *Enricher) Enrich(ctx context.Context, bom *cdx.BOM) error {
	if bom == nil || bom.Components == nil {
		return nil
	}

	components := *bom.Components
	var purls []string
	for i := range components {
		comp := &components[i]
		if componentNeedsResolve(comp) {
			purls = append(purls, comp.PackageURL)
		}
	}

	outcomes := e.resolvePurls(ctx, lo.Uniq(purls))

	var failed []*componentError
	reported := make(map[string]struct{})
	for i := range components {
		comp := &components[i]
		if comp.PackageURL == "" {
			if !purlNotExpected(comp.Type) {
				failed = append(failed, &componentError{name: comp.Name, err: fmt.Errorf("component %q (type %q) has no purl", comp.Name, comp.Type)})
			}
			continue
		}
		if !componentNeedsResolve(comp) {
			continue
		}

		outcome := outcomes[comp.PackageURL]
		if outcome.err != nil {
			if _, done := reported[comp.PackageURL]; !done {
				reported[comp.PackageURL] = struct{}{}
				failed = append(failed, &componentError{name: comp.Name, purl: comp.PackageURL, err: outcome.err})
			}
			continue
		}

		if comp.ExternalReferences == nil {
			comp.ExternalReferences = &[]cdx.ExternalReference{}
		}
		// A component carrying two links of the same type fails ISPRAS validation,
		// and downstream images re-enrich an already enriched BOM. A source
		// distribution an older enrichment left without a digest is replaced
		// rather than kept: the base image it came from cannot be fixed from here,
		// and keeping it would carry the unvalidatable link into this SBOM too.
		if existing, idx, ok := findRefType(*comp.ExternalReferences, outcome.ref.Type); ok {
			if hasHashes(existing) || outcome.ref.Hashes == nil {
				continue
			}
			(*comp.ExternalReferences)[idx] = outcome.ref
		} else {
			*comp.ExternalReferences = append(*comp.ExternalReferences, outcome.ref)
		}
	}

	if len(failed) > 0 {
		return newComponentError(failed)
	}

	// The BOM-wide list is derived from the final component references: a link
	// replaced on one component may still be carried, with a digest, by another.
	seen := make(map[string]cdx.ExternalReference)
	for _, comp := range components {
		if comp.ExternalReferences == nil {
			continue
		}
		for _, ref := range *comp.ExternalReferences {
			seen[refKey(ref)] = ref
		}
	}

	if len(seen) > 0 {
		bomRefs := lo.Values(seen)
		bom.ExternalReferences = &bomRefs
		logboek.Context(ctx).Debug().LogF("Enriched SBOM with %d external references\n", len(bomRefs))
	}

	return nil
}

type purlOutcome struct {
	ref cdx.ExternalReference
	err error
}

func (e *Enricher) resolvePurls(ctx context.Context, purls []string) map[string]*purlOutcome {
	outcomes := make(map[string]*purlOutcome, len(purls))
	for _, purl := range purls {
		outcomes[purl] = &purlOutcome{}
	}

	var g errgroup.Group
	g.SetLimit(10)
	for _, purl := range purls {
		g.Go(func() error {
			outcome := outcomes[purl]

			res, err := e.Resolve(ctx, purl)
			if err != nil {
				outcome.err = err
				return nil
			}

			if err := validateRefKind(res.Kind); err != nil {
				outcome.err = err
				return nil
			}

			if err := validateRefHashes(res.Kind, res.Hashes); err != nil {
				outcome.err = err
				return nil
			}

			outcome.ref = cdx.ExternalReference{
				URL:     res.URL,
				Type:    cdx.ExternalReferenceType(res.Kind),
				Comment: cyclonedxutil.ExternalReferenceCommentResolved,
				Hashes:  refHashes(res.Kind, res.Hashes),
			}
			return nil
		})
	}
	_ = g.Wait()

	return outcomes
}

// newComponentError renders per-component failure lines. Resolver-unavailable
// failures are collapsed into one summary line: after the breaker trips every
// remaining PURL fails with the same sentinel, and repeating it per component
// only obscures the real failures.
func newComponentError(failed []*componentError) *ComponentError {
	var details strings.Builder
	var innerErrs []error
	var unavailablePurls int
	for _, ce := range failed {
		innerErrs = append(innerErrs, ce.err)
		if errors.Is(ce.err, ErrResolverUnavailable) {
			unavailablePurls++
			continue
		}
		if ce.purl != "" {
			fmt.Fprintf(&details, "    - component: %s (%s): %s\n", ce.name, ce.purl, ce.err)
		} else {
			fmt.Fprintf(&details, "    - component: %s: %s\n", ce.name, ce.err)
		}
	}
	if unavailablePurls > 0 {
		fmt.Fprintf(&details, "    - PURL resolver unavailable: resolution skipped for %d package URLs\n", unavailablePurls)
	}
	return &ComponentError{
		err:     errors.Join(innerErrs...),
		details: details.String(),
	}
}

func componentNeedsResolve(comp *cdx.Component) bool {
	return comp.PackageURL != "" && comp.Version != "(devel)"
}

func refKey(ref cdx.ExternalReference) string {
	return ref.URL + "|" + string(ref.Type)
}

func hashContentDescription(algorithm string) string {
	if algorithm == hashAlgStreebog512 {
		return "128 hexadecimal characters"
	}
	return "64 hexadecimal characters"
}

// refHashes carries the resolver hashes into the reference. Only a source
// distribution needs them: for a vcs link the schema demands none and the
// resolver reports none either.
func refHashes(kind string, hashes []Hash) *[]cdx.Hash {
	if cdx.ExternalReferenceType(kind) != cdx.ERTypeSourceDistribution {
		return nil
	}

	cdxHashes := lo.Map(hashes, func(hash Hash, _ int) cdx.Hash {
		return cdx.Hash{
			Algorithm: cdx.HashAlgorithm(hash.Algorithm),
			Value:     hash.Content,
		}
	})

	return &cdxHashes
}

func hasHashes(ref cdx.ExternalReference) bool {
	return ref.Hashes != nil && len(*ref.Hashes) > 0
}

func findRefType(refs []cdx.ExternalReference, refType cdx.ExternalReferenceType) (cdx.ExternalReference, int, bool) {
	return lo.FindIndexOf(refs, func(ref cdx.ExternalReference) bool {
		return ref.Type == refType
	})
}
