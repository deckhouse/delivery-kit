package externalref

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

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
	Resolve  func(ctx context.Context, purl string) (*ResolveResult, error)
	CheckVCS func(ctx context.Context, vcsURL string) (*ResolveResult, error)

	vcsChecks singleflight.Group
}

func NewEnricher(
	resolve func(ctx context.Context, purl string) (*ResolveResult, error),
	checkVCS func(ctx context.Context, vcsURL string) (*ResolveResult, error),
) *Enricher {
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

	var g errgroup.Group
	g.SetLimit(10)

	var seen sync.Map

	components := *bom.Components
	compErrs := make([]*componentError, len(components))
	for i := range components {
		comp := &components[i]
		g.Go(func() error {
			if err := e.enrichComponent(ctx, comp, &seen); err != nil {
				compErrs[i] = &componentError{name: comp.Name, purl: comp.PackageURL, err: err}
			}
			return nil
		})
	}

	_ = g.Wait()

	if failed := lo.Compact(compErrs); len(failed) > 0 {
		var details strings.Builder
		var innerErrs []error
		for _, ce := range failed {
			fmt.Fprintf(&details, "    - component: %s: %s\n", ce.name, ce.err)
			innerErrs = append(innerErrs, ce.err)
		}
		return &ComponentError{
			err:     errors.Join(innerErrs...),
			details: details.String(),
		}
	}

	var bomRefs []cdx.ExternalReference
	seen.Range(func(_, value any) bool {
		bomRefs = append(bomRefs, value.(cdx.ExternalReference))
		return true
	})

	if len(bomRefs) > 0 {
		bom.ExternalReferences = &bomRefs
		logboek.Context(ctx).Debug().LogF("Enriched SBOM with %d external references\n", len(bomRefs))
	}

	return nil
}

func (e *Enricher) enrichComponent(ctx context.Context, comp *cdx.Component, seen *sync.Map) error {
	if comp.ExternalReferences != nil && len(*comp.ExternalReferences) > 0 {
		for _, ref := range *comp.ExternalReferences {
			seen.Store(ref.URL+"|"+string(ref.Type), ref)
		}
	}

	if comp.PackageURL == "" {
		if purlNotExpected(comp.Type) {
			return nil
		}
		return fmt.Errorf("component %q (type %q) has no purl", comp.Name, comp.Type)
	}

	if comp.Version == "(devel)" {
		return nil
	}

	var unconfirmed error
	if vcsURL, ok := knownVCSLink(comp); ok {
		unconfirmed = e.checkVCSLink(ctx, vcsURL)
		if unconfirmed == nil {
			return nil
		}
		if isInfraFailure(unconfirmed) {
			return unconfirmed
		}
		unconfirmed = fmt.Errorf("vcs link %q not confirmed: %w", vcsURL, unconfirmed)
	}

	res, err := e.Resolve(ctx, comp.PackageURL)
	if err != nil {
		if unconfirmed != nil {
			return fmt.Errorf("%w; %w", unconfirmed, err)
		}
		return err
	}

	if err := validateRefKind(res.Kind); err != nil {
		if unconfirmed != nil {
			return fmt.Errorf("%w; %w", unconfirmed, err)
		}
		return err
	}

	extRef := cdx.ExternalReference{
		URL:  res.URL,
		Type: cdx.ExternalReferenceType(res.Kind),
	}

	if comp.ExternalReferences == nil {
		comp.ExternalReferences = &[]cdx.ExternalReference{}
	}
	if unconfirmed != nil {
		logboek.Context(ctx).Warn().LogF("WARNING: component %s (%s): %s; replaced with %s %q resolved from purl\n", comp.Name, comp.PackageURL, unconfirmed, extRef.Type, extRef.URL)
		*comp.ExternalReferences = lo.Reject(*comp.ExternalReferences, func(ref cdx.ExternalReference, _ int) bool {
			return ref.Type == cdx.ERTypeVCS
		})
	}
	*comp.ExternalReferences = append(*comp.ExternalReferences, extRef)

	seen.Store(res.URL+"|"+res.Kind, extRef)

	return nil
}

// checkVCSLink returns nil when the resolver confirms the link, an infrastructure
// failure when the resolver could not be asked, and the reason otherwise. A link
// shared by several components is checked once per enrichment.
func (e *Enricher) checkVCSLink(ctx context.Context, vcsURL string) error {
	_, err, _ := e.vcsChecks.Do(vcsURL, func() (any, error) {
		res, err := e.CheckVCS(ctx, vcsURL)
		if err != nil {
			return nil, err
		}
		// For the url check kind "vcs" and a confirmed status are the same
		// verdict: the resolver derives the row status from kind alone.
		if cdx.ExternalReferenceType(res.Kind) != cdx.ERTypeVCS {
			return nil, fmt.Errorf("resolver reports kind %q", res.Kind)
		}
		return nil, nil
	})
	return err
}

func isInfraFailure(err error) bool {
	if errors.Is(err, ErrResolverUnavailable) {
		return true
	}
	var classified *ClassifiedError
	return errors.As(err, &classified) && classified.Class == FailureClassInfra
}

func knownVCSLink(comp *cdx.Component) (string, bool) {
	if comp.ExternalReferences == nil {
		return "", false
	}
	ref, ok := lo.Find(*comp.ExternalReferences, func(ref cdx.ExternalReference) bool {
		return ref.Type == cdx.ERTypeVCS && ref.URL != ""
	})
	return ref.URL, ok
}
