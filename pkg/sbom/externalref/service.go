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
	"github.com/werf/werf/v3/pkg/werf"
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

	return backoff.Retry(ctx, func() (*ResolveResult, error) {
		return s.doQuery(ctx, u, op)
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
}

func (s *Service) doQuery(ctx context.Context, u, op string) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, backoff.Permanent(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s: create request: %w", op, err)))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, s.infraError(ctx, op, fmt.Errorf("%s: %w", op, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, s.infraError(ctx, op, fmt.Errorf("%s: read body: %w", op, err))
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("%s: unexpected status %s", op, statusErrorDetail(resp.Status, resp.Header.Get("Content-Type"), body))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, s.classify(FailureClassInfra, err)
		}
		return nil, backoff.Permanent(s.classify(FailureClassContent, err))
	}

	var result ResolveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s: parse response: %w", op, err)))
	}

	if result.URL == "" {
		return nil, backoff.Permanent(s.classify(FailureClassContent, fmt.Errorf("%s: %w", op, ErrEmptyURL)))
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

// infraError guards canceled resolutions: errgroup cancels sibling workers with the
// first failure as the context cause and net/http returns context.Cause(ctx), so a
// canceled resolve would otherwise embed another image's entire error report.
// Cancellation is terminal for this build and says nothing about resolver health,
// so it is permanent and not counted by the breaker.
func (s *Service) infraError(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return backoff.Permanent(&ClassifiedError{Class: FailureClassInfra, Err: fmt.Errorf("%s: %w", op, ctxErr)})
	}
	return s.classify(FailureClassInfra, err)
}

const maxErrorBodyDetailLen = 200

// statusErrorDetail builds the error detail for a non-200 resolver response: HTML
// bodies are proxy boilerplate carrying nothing beyond the status line and are
// dropped, other bodies are collapsed to a single line and truncated.
func statusErrorDetail(status, contentType string, body []byte) string {
	detail := strings.Join(strings.Fields(string(body)), " ")
	if detail == "" || strings.Contains(contentType, "text/html") || strings.HasPrefix(detail, "<") {
		return status
	}
	if runes := []rune(detail); len(runes) > maxErrorBodyDetailLen {
		detail = string(runes[:maxErrorBodyDetailLen]) + "..."
	}
	return fmt.Sprintf("%s: %s", status, detail)
}
