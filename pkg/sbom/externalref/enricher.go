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
			if ce.purl != "" {
				fmt.Fprintf(&details, "    - component: %s (%s): %s\n", ce.name, ce.purl, ce.err)
			} else {
				fmt.Fprintf(&details, "    - component: %s: %s\n", ce.name, ce.err)
			}
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

	res, err := e.Resolve(ctx, comp.PackageURL)
	if err != nil {
		return err
	}

	if err := validateRefKind(res.Kind); err != nil {
		return err
	}

	extRef := cdx.ExternalReference{
		URL:  res.URL,
		Type: cdx.ExternalReferenceType(res.Kind),
	}

	if comp.ExternalReferences == nil {
		comp.ExternalReferences = &[]cdx.ExternalReference{}
	}
	*comp.ExternalReferences = append(*comp.ExternalReferences, extRef)

	seen.Store(res.URL+"|"+res.Kind, extRef)

	return nil
}
