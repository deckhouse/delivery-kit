package externalref

import (
	"context"
	"errors"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var ErrExternalRefEnrich = errors.New("enrich external references")

const EnvName = "WERF_EXTERNAL_REFS_SERVER_URL"

type ExternalRefPatcher struct {
	enricher *Enricher
}

func NewExternalRefPatcher() (*ExternalRefPatcher, error) {
	serverURL := os.Getenv(EnvName)
	if serverURL == "" {
		return nil, fmt.Errorf("%s env var is required", EnvName)
	}

	svc := NewService(ServiceConfig{ServerURL: serverURL})
	return &ExternalRefPatcher{enricher: NewEnricher(svc.Resolve)}, nil
}

func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	if err := p.enricher.Enrich(ctx, bom); err != nil {
		return bom, fmt.Errorf("enrich external references: %w", errors.Join(err, ErrExternalRefEnrich))
	}

	return bom, nil
}
