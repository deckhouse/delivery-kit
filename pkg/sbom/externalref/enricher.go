package externalref

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
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
// validated with: one carrying no STREEBOG digest at all, one whose STREEBOG
// digest is malformed, or one whose non-STREEBOG digest is in an algorithm the
// CycloneDX 1.6 schema does not define. A well-formed digest in an accepted
// algorithm travels along untouched — the schema asks for a STREEBOG one among
// the hashes, not instead of them, and a resolver that also reports the SHA-256
// of the archive must not fail a build.
func validateRefHashes(kind string, hashes []Hash) error {
	if cdx.ExternalReferenceType(kind) != cdx.ERTypeSourceDistribution {
		return nil
	}

	var streebogHashes int
	for _, hash := range hashes {
		contentRe, ok := hashContentRe[hash.Algorithm]
		if !ok {
			// A non-STREEBOG digest travels along, but only if its algorithm is a
			// member of the schema enum: with build-time schema validation off,
			// nothing else stops an unknown algorithm from reaching the registry.
			allowed, err := cyclonedxutil.HashAlgorithmAllowed(hash.Algorithm)
			if err != nil {
				return fmt.Errorf("enrich: check hash algorithm %q: %w", hash.Algorithm, err)
			}
			if !allowed {
				return fmt.Errorf("enrich: source distribution hash algorithm %q is not in the CycloneDX 1.6 schema", hash.Algorithm)
			}
			continue
		}
		if !contentRe.MatchString(hash.Content) {
			return fmt.Errorf("enrich: source distribution hash %q has invalid content %q, expected %s", hash.Algorithm, hash.Content, hashContentDescription(hash.Algorithm))
		}
		streebogHashes++
	}

	if streebogHashes == 0 {
		return fmt.Errorf("enrich: source distribution has no %q or %q hash, got %s", hashAlgStreebog256, hashAlgStreebog512, hashAlgorithms(hashes))
	}

	return nil
}

// hashAlgorithms renders the algorithms the resolver reported, for the error
// raised when a source distribution carries schema-valid hashes (a lone SHA-256,
// say) but no STREEBOG digest among them.
func hashAlgorithms(hashes []Hash) string {
	if len(hashes) == 0 {
		return "no hashes"
	}

	return strings.Join(lo.Map(hashes, func(hash Hash, _ int) string {
		return strconv.Quote(hash.Algorithm)
	}), ", ")
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
	Resolve  func(ctx context.Context, purl string) (*ResolveResult, error)
	CheckVCS func(ctx context.Context, vcsURL string) (*ResolveResult, error)
}

func NewEnricher(resolve, checkVCS func(ctx context.Context, subject string) (*ResolveResult, error)) *Enricher {
	return &Enricher{Resolve: resolve, CheckVCS: checkVCS}
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

	// A link the SBOM already carries — the repository a package manager recorded
	// for its package — is verified as a URL, which the resolver answers without
	// knowing the package: a purl it cannot resolve (one naming a package index
	// that is not published where the resolver looks) no longer fails a component
	// whose source is known. Only an unconfirmed link falls back to purl resolution.
	var vcsURLs []string
	for i := range components {
		comp := &components[i]
		if !componentNeedsResolve(comp) {
			continue
		}
		if vcsURL, ok := knownVCSLink(comp); ok {
			vcsURLs = append(vcsURLs, vcsURL)
		}
	}

	vcsOutcomes := e.checkVCSLinks(ctx, lo.Uniq(vcsURLs))

	var purls []string
	for i := range components {
		comp := &components[i]
		if !componentNeedsResolve(comp) || internalIdentity(comp) {
			continue
		}
		if vcsURL, ok := knownVCSLink(comp); ok && vcsOutcomes[vcsURL].unconfirmed == nil {
			continue
		}
		purls = append(purls, comp.PackageURL)
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

		var unconfirmed error
		vcsURL, hasVCS := knownVCSLink(comp)
		if hasVCS {
			vcsOutcome := vcsOutcomes[vcsURL]
			if vcsOutcome.err != nil {
				if _, done := reported[comp.PackageURL]; !done {
					reported[comp.PackageURL] = struct{}{}
					failed = append(failed, &componentError{name: comp.Name, purl: comp.PackageURL, err: vcsOutcome.err})
				}
				continue
			}
			if vcsOutcome.unconfirmed == nil {
				continue
			}
			unconfirmed = fmt.Errorf("vcs link %q not confirmed: %w", vcsURL, vcsOutcome.unconfirmed)
		}

		// A link to the upstream an internally named component was built from is kept
		// only when confirmed, and its absence is no failure.
		if internalIdentity(comp) {
			if unconfirmed != nil {
				logboek.Context(ctx).Warn().LogF("WARNING: component %s (%s): %s; dropped\n", comp.Name, comp.PackageURL, unconfirmed)
				*comp.ExternalReferences = lo.Reject(*comp.ExternalReferences, func(ref cdx.ExternalReference, _ int) bool {
					return ref.Type == cdx.ERTypeVCS
				})
			}
			continue
		}

		outcome := outcomes[comp.PackageURL]
		if outcome.err != nil {
			if _, done := reported[comp.PackageURL]; !done {
				reported[comp.PackageURL] = struct{}{}
				err := outcome.err
				if unconfirmed != nil {
					err = fmt.Errorf("%w; %w", unconfirmed, outcome.err)
				}
				failed = append(failed, &componentError{name: comp.Name, purl: comp.PackageURL, err: err})
			}
			continue
		}

		if comp.ExternalReferences == nil {
			comp.ExternalReferences = &[]cdx.ExternalReference{}
		}
		if unconfirmed != nil {
			logboek.Context(ctx).Warn().LogF("WARNING: component %s (%s): %s; replaced with %s %q resolved from purl\n", comp.Name, comp.PackageURL, unconfirmed, outcome.ref.Type, outcome.ref.URL)
			*comp.ExternalReferences = lo.Reject(*comp.ExternalReferences, func(ref cdx.ExternalReference, _ int) bool {
				return ref.Type == cdx.ERTypeVCS
			})
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

// vcsOutcome separates the resolver refusing to vouch for a link (unconfirmed:
// a repository it reports as not a VCS, or one it has no answer for) from the
// resolver being unreachable (err): the first falls back to purl resolution, the
// second is the same terminal failure a resolve call would hit.
type vcsOutcome struct {
	unconfirmed error
	err         error
}

func (e *Enricher) checkVCSLinks(ctx context.Context, vcsURLs []string) map[string]*vcsOutcome {
	outcomes := make(map[string]*vcsOutcome, len(vcsURLs))
	for _, vcsURL := range vcsURLs {
		outcomes[vcsURL] = &vcsOutcome{}
	}

	var g errgroup.Group
	g.SetLimit(resolveConcurrency)
	for _, vcsURL := range vcsURLs {
		g.Go(func() error {
			outcome := outcomes[vcsURL]

			res, err := e.CheckVCS(ctx, vcsURL)
			if err != nil {
				if isInfraFailure(err) {
					outcome.err = err
				} else {
					outcome.unconfirmed = err
				}
				return nil
			}

			// For the url check kind "vcs" and a confirmed status are the same
			// verdict: the resolver derives the row status from kind alone.
			if cdx.ExternalReferenceType(res.Kind) != cdx.ERTypeVCS {
				outcome.unconfirmed = fmt.Errorf("resolver reports kind %q", res.Kind)
			}
			return nil
		})
	}
	_ = g.Wait()

	return outcomes
}

func isInfraFailure(err error) bool {
	if errors.Is(err, ErrResolverUnavailable) {
		return true
	}
	var classified *ClassifiedError
	return errors.As(err, &classified) && classified.Class == FailureClassInfra
}

// knownVCSLink returns the component's vcs link. A BOM reaching enrichment
// carries at most one vcs link per component: merged BOMs are canonicalized
// first, and syft emits at most one. A second link only shows up in a foreign
// SBOM and is handled by the fallback.
func knownVCSLink(comp *cdx.Component) (string, bool) {
	if comp.ExternalReferences == nil {
		return "", false
	}
	ref, ok := lo.Find(*comp.ExternalReferences, func(ref cdx.ExternalReference) bool {
		return ref.Type == cdx.ERTypeVCS && ref.URL != ""
	})
	return ref.URL, ok
}

const resolveConcurrency = 10

// maxResolvePassDuration caps the deadline the purl pass gets. A pass where every
// subject burns its whole retry budget would otherwise run for hours on a large
// component list, and such a build fails at the end anyway.
const maxResolvePassDuration = 15 * time.Minute

// resolvePassDuration sizes the pass after the work it can have: the subjects run
// resolveConcurrency at a time, each bounded by the per-subject retry budget.
func resolvePassDuration(purls int) time.Duration {
	batches := (purls + resolveConcurrency - 1) / resolveConcurrency
	if batches < 1 {
		batches = 1
	}
	return min(time.Duration(batches)*(defaultMaxElapsedTime+defaultServiceTimeout), maxResolvePassDuration)
}

func (e *Enricher) resolvePurls(ctx context.Context, purls []string) map[string]*purlOutcome {
	outcomes := make(map[string]*purlOutcome, len(purls))
	for _, purl := range purls {
		outcomes[purl] = &purlOutcome{}
	}

	ctx, cancel := context.WithTimeout(ctx, resolvePassDuration(len(purls)))
	defer cancel()

	var g errgroup.Group
	g.SetLimit(resolveConcurrency)
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

// internalIdentity reports a component nativegate named by something only this build
// knows: a prepared source package or an original source package, both marked with the
// identity nativegate gave them, and a component read out of a binary whose source is a
// package of the private registry the factory builds from. No resolver knows any of them
// under that purl, and sending one there would publish an internal identity, so they are
// not resolved and their lack of a link is no failure.
func internalIdentity(comp *cdx.Component) bool {
	if lo.ContainsBy(lo.FromPtr(comp.Properties), func(property cdx.Property) bool {
		return property.Name == cyclonedxutil.PropertyOriginalSource &&
			(strings.HasPrefix(property.Value, preparedSourcePrefix) || strings.HasPrefix(property.Value, originalSourcePrefix))
	}) {
		return true
	}

	purl, err := packageurl.FromString(comp.PackageURL)
	if err != nil || purl.Type != packageurl.TypeGeneric {
		return false
	}

	return purl.Qualifiers.Map()["source_kind"] == pmSourceKind
}

// The identities nativegate gives the source packages of this build, and the source kind
// a component of a verified composition carries when it came from a package of the
// factory's own registry.
const (
	preparedSourcePrefix = "urn:dk:prepared-source:"
	originalSourcePrefix = "pm-source:"
	pmSourceKind         = "pm"
)

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
