package externalref

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/werf"
)

const (
	defaultServiceTimeout = 5 * time.Second
	defaultMaxElapsedTime = 10 * time.Second
)

type ServiceConfig struct {
	ServerURL  string
	Timeout    time.Duration
	HTTPClient *http.Client
	Breaker    *ResolverBreaker
}

type Service struct {
	serverURL  string
	httpClient *http.Client
	breaker    *ResolverBreaker
}

func NewService(cfg ServiceConfig) *Service {
	serverURL := strings.TrimRight(cfg.ServerURL, "/")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultServiceTimeout
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: werf.NewUserAgentTransport(http.DefaultTransport),
			Timeout:   timeout,
		}
	}

	return &Service{
		serverURL:  serverURL,
		httpClient: httpClient,
		breaker:    cfg.Breaker,
	}
}

func (s *Service) Resolve(ctx context.Context, purl string) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, err
	}

	u := fmt.Sprintf("%s/api/v1/resolve?purl=%s", s.serverURL, url.QueryEscape(purl))

	return backoff.Retry(ctx, func() (*ResolveResult, error) {
		return s.doResolve(ctx, u, purl)
	},
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxElapsedTime(defaultMaxElapsedTime),
		backoff.WithNotify(func(err error, duration time.Duration) {
			logboek.Context(ctx).Warn().LogF(
				"WARNING: resolve PURL failed, retrying in %v: %s\n",
				duration, err,
			)
		}),
	)
}

func (s *Service) doResolve(ctx context.Context, u, purl string) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, backoff.Permanent(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("resolve %q: create request: %w", purl, err)))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, s.classify(FailureClassInfra, fmt.Errorf("resolve %q: %w", purl, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, s.classify(FailureClassInfra, fmt.Errorf("resolve %q: read body: %w", purl, err))
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("resolve %q: unexpected status %d: %s", purl, resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, s.classify(FailureClassInfra, err)
		}
		return nil, backoff.Permanent(s.classify(FailureClassContent, err))
	}

	var result ResolveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("resolve %q: parse response: %w", purl, err)))
	}

	if result.URL == "" {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("resolve %q: %w", purl, ErrEmptyURL)))
	}

	if s.breaker != nil {
		s.breaker.RecordSuccess()
	}

	return &result, nil
}

func (s *Service) breakerAllow() error {
	if s.breaker == nil {
		return nil
	}
	return s.breaker.Allow()
}

func (s *Service) classify(class FailureClass, err error) error {
	classified := &ClassifiedError{Class: class, Err: err}
	if s.breaker != nil {
		s.breaker.RecordFailure(class, classified)
	}
	return classified
}
