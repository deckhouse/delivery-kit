package convergefailure

import (
	"context"
	"errors"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v2/pkg/sbom/externalref"
)

// componentEnrichError produces the real error an image gets when enrichment
// fails for a component, wrapped exactly the way ExternalRefPatcher wraps it, so
// tests exercise the same error chain the build phase sees.
func componentEnrichError(componentName string) error {
	enricher := externalref.NewEnricher(func(ctx context.Context, purl string) (*externalref.ResolveResult, error) {
		return nil, errors.New("empty url")
	})
	bom := &cdx.BOM{Components: &[]cdx.Component{{Name: componentName, PackageURL: "pkg:apk/alpine/" + componentName + "@1.0.0"}}}

	err := enricher.Enrich(context.Background(), bom)
	if err == nil {
		panic("expected enrich to fail")
	}

	return errors.Join(err, externalref.ErrExternalRefEnrich)
}

// unwrapLogboek collapses the soft line wrapping logboek applies to warnings —
// it breaks a long line with a "↵" marker — so a single logical line can be
// matched as one substring.
func unwrapLogboek(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "↵", "")), " ")
}

func trippedBreaker(endpoint string) *externalref.ResolverBreaker {
	breaker := externalref.NewResolverBreaker(endpoint)
	for i := 0; i < 10; i++ {
		breaker.RecordFailure(externalref.FailureClassInfra, errors.New("connection refused"))
	}
	return breaker
}
