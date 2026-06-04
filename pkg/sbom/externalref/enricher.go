package externalref

import (
	"context"
	"fmt"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/sync/errgroup"

	"github.com/werf/logboek"
)

type Enricher struct {
	resolve func(ctx context.Context, purl string) (*ResolveResult, error)
}

func NewEnricher(resolve func(ctx context.Context, purl string) (*ResolveResult, error)) *Enricher {
	return &Enricher{resolve: resolve}
}

func (e *Enricher) Enrich(ctx context.Context, bom *cdx.BOM) error {
	if bom == nil || bom.Components == nil {
		return nil
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	var mu sync.Mutex
	seen := make(map[string]bool)
	var bomRefs []cdx.ExternalReference

	components := *bom.Components
	for i := range components {
		comp := &components[i]
		g.Go(func() error {
			if comp.PackageURL == "" {
				return fmt.Errorf("enrich: component %q has no purl", comp.Name)
			}

			res, err := e.resolve(ctx, comp.PackageURL)
			if err != nil {
				return fmt.Errorf("enrich %q: %w", comp.PackageURL, err)
			}

			extRef := cdx.ExternalReference{
				URL:  res.URL,
				Type: cdx.ExternalReferenceType(res.Kind),
			}

			if comp.ExternalReferences == nil {
				comp.ExternalReferences = &[]cdx.ExternalReference{}
			}
			*comp.ExternalReferences = append(*comp.ExternalReferences, extRef)

			mu.Lock()
			defer mu.Unlock()

			key := res.URL + "|" + res.Kind
			if !seen[key] {
				seen[key] = true
				bomRefs = append(bomRefs, extRef)
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	if len(bomRefs) > 0 {
		bom.ExternalReferences = &bomRefs
		logboek.Context(ctx).Debug().LogF("Enriched SBOM with %d external references\n", len(bomRefs))
	}

	return nil
}
