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
	u := fmt.Sprintf("%s/api/v1/resolve?purl=%s", s.serverURL, url.QueryEscape(purl))
	return s.query(ctx, u, "resolve", purl)
}

// CheckVCS asks the resolver to verify a repository URL the SBOM already carries,
// for instance the one a package manager recorded for its package. The resolver
// keys the answer by the URL alone, so the verdict does not depend on the purl
// that led to the link.
func (s *Service) CheckVCS(ctx context.Context, vcsURL string) (*ResolveResult, error) {
	u := fmt.Sprintf("%s/api/v1/vcs?url=%s", s.serverURL, url.QueryEscape(vcsURL))
	return s.query(ctx, u, "check vcs", vcsURL)
}

func (s *Service) query(ctx context.Context, u, op, subject string) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, err
	}

	res, err := backoff.Retry(ctx, func() (*ResolveResult, error) {
		return s.doQuery(ctx, u, op, subject)
	},
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxElapsedTime(defaultMaxElapsedTime),
		backoff.WithNotify(func(err error, duration time.Duration) {
			logboek.Context(ctx).Warn().LogF(
				"WARNING: %s %q failed, retrying in %v: %s\n",
				op, subject, duration, err,
			)
		}),
	)
	// A context canceled between attempts or during the backoff wait comes back from
	// the retry loop as the bare cancellation cause: errgroup cancels sibling workers
	// with the first failure as the cause, so the error would otherwise embed another
	// image's entire report.
	if err != nil && ctx.Err() != nil {
		return nil, &ClassifiedError{Class: FailureClassInfra, Err: fmt.Errorf("%s %q: %w", op, subject, ctx.Err())}
	}

	return res, err
}

func (s *Service) doQuery(ctx context.Context, u, op, subject string) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, backoff.Permanent(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s %q: create request: %w", op, subject, err)))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, s.classify(FailureClassInfra, fmt.Errorf("%s %q: %w", op, subject, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, s.classify(FailureClassInfra, fmt.Errorf("%s %q: read body: %w", op, subject, err))
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%s %q: unexpected status %d: %s", op, subject, resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, s.classify(FailureClassInfra, err)
		}
		return nil, backoff.Permanent(s.classify(FailureClassContent, err))
	}

	var result ResolveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s %q: parse response: %w", op, subject, err)))
	}

	if result.URL == "" {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s %q: %w", op, subject, ErrEmptyURL)))
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
