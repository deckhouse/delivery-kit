package externalref

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"

	"github.com/werf/logboek"
)

func validateRefKind(kind string) error {
	switch cdx.ExternalReferenceType(kind) {
	case cdx.ERTypeVCS, cdx.ERTypeWebsite, cdx.ERTypeIssueTracker, cdx.ERTypeAdvisories,
		cdx.ERTypeBOM, cdx.ERTypeChat, cdx.ERTypeDocumentation, cdx.ERTypeDistribution,
		cdx.ERTypeLicense, cdx.ERTypeOther, cdx.ERTypeReleaseNotes, cdx.ERTypeSecurityContact,
		cdx.ERTypeSocial, cdx.ERTypeSupport, cdx.ERTypeEvidence, cdx.ERTypeFormulation,
		cdx.ERTypeConfiguration, cdx.ERTypeBuildMeta, cdx.ERTypeBuildSystem,
		cdx.ERTypeAttestation, cdx.ERTypeThreatModel, cdx.ERTypeRiskAssessment,
		cdx.ERTypeMaturityReport, cdx.ERTypeComponentAnalysisReport, cdx.ERTypeDynamicAnalysisReport,
		cdx.ERTypeStaticAnalysisReport, cdx.ERTypePentestReport, cdx.ERTypeCertificationReport,
		cdx.ERTypeQualityMetrics, cdx.ERTypePOAM, cdx.ERTypeRuntimeAnalysisReport,
		cdx.ERTypeExploitabilityStatement, cdx.ERTypeAdversaryModel, cdx.ERTypeModelCard,
		cdx.ERTypeDistributionIntake, cdx.ERTypeDigitalSignature, cdx.ERTypeElectronicSignature,
		cdx.ERTypeCodifiedInfrastructure, cdx.ERTypeLog, cdx.ERTypeMailingList,
		cdx.ERTypeRFC9116, cdx.ERTypeSourceDistribution, cdx.ERTypeVulnerabilityAssertion:
		return nil
	default:
		return fmt.Errorf("enrich: unknown external reference kind %q", kind)
	}
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
	seen := make(map[string]cdx.ExternalReference)
	var purls []string
	for i := range components {
		comp := &components[i]
		if comp.ExternalReferences != nil {
			for _, ref := range *comp.ExternalReferences {
				seen[refKey(ref)] = ref
			}
		}
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
		*comp.ExternalReferences = append(*comp.ExternalReferences, outcome.ref)
		seen[refKey(outcome.ref)] = outcome.ref
	}

	if len(failed) > 0 {
		return newComponentError(failed)
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

			outcome.ref = cdx.ExternalReference{
				URL:  res.URL,
				Type: cdx.ExternalReferenceType(res.Kind),
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
