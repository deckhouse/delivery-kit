package externalref

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var ErrExternalRefEnrich = errors.New("enrich external references")

const (
	EnvName        = "WERF_EXTERNAL_REFS_SERVER_URL"
	TimeoutEnvName = "WERF_EXTERNAL_REFS_TIMEOUT"
)

type ExternalRefPatcher struct {
	enricher *Enricher
}

type NewExternalRefPatcherOptions struct {
	Breaker *ResolverBreaker
}

func NewExternalRefPatcher(opts NewExternalRefPatcherOptions) (*ExternalRefPatcher, error) {
	cfg, err := serviceConfigFromEnv()
	if err != nil {
		return nil, err
	}
	cfg.Breaker = opts.Breaker

	svc := NewService(cfg)
	return &ExternalRefPatcher{enricher: NewEnricher(svc.Resolve, svc.CheckVCS)}, nil
}

func serviceConfigFromEnv() (ServiceConfig, error) {
	serverURL := os.Getenv(EnvName)
	if serverURL == "" {
		return ServiceConfig{}, fmt.Errorf("%s env var is required", EnvName)
	}

	timeout := defaultServiceTimeout
	if value := os.Getenv(TimeoutEnvName); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return ServiceConfig{}, fmt.Errorf("bad %s variable value %q: %w", TimeoutEnvName, value, err)
		}
		if parsed <= 0 {
			return ServiceConfig{}, fmt.Errorf("bad %s variable value %q: must be positive", TimeoutEnvName, value)
		}
		timeout = parsed
	}

	return ServiceConfig{ServerURL: serverURL, Timeout: timeout}, nil
}

func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	if err := p.enricher.Enrich(ctx, bom); err != nil {
		return bom, fmt.Errorf("enrich external references: %w", errors.Join(err, ErrExternalRefEnrich))
	}

	return bom, nil
}
