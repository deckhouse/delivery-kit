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
	EnvName             = "WERF_EXTERNAL_REFS_SERVER_URL"
	TimeoutEnvName      = "WERF_EXTERNAL_REFS_TIMEOUT"
	RetryTimeoutEnvName = "WERF_EXTERNAL_REFS_RETRY_TIMEOUT"
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

	timeout, err := durationFromEnv(TimeoutEnvName, defaultServiceTimeout)
	if err != nil {
		return ServiceConfig{}, err
	}

	maxElapsedTime, err := durationFromEnv(RetryTimeoutEnvName, defaultMaxElapsedTime)
	if err != nil {
		return ServiceConfig{}, err
	}

	return ServiceConfig{ServerURL: serverURL, Timeout: timeout, MaxElapsedTime: maxElapsedTime}, nil
}

func durationFromEnv(envName string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(envName)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("bad %s variable value %q: %w", envName, value, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("bad %s variable value %q: must be positive", envName, value)
	}

	return parsed, nil
}

func (p *ExternalRefPatcher) Apply(ctx context.Context, bom *cdx.BOM) (*cdx.BOM, error) {
	if err := p.enricher.Enrich(ctx, bom); err != nil {
		return bom, fmt.Errorf("enrich external references: %w", errors.Join(err, ErrExternalRefEnrich))
	}

	return bom, nil
}
