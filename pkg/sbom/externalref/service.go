package externalref

import (
	"context"
	"encoding/json"
	"errors"
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

// A purl the resolver has never seen is answered from its own cold path: it queries
// deps.dev and libraries.io before it can say anything, which takes far longer than
// the answer it later serves from its database, and until that finishes it reports a
// kind of "unknown". The per-request timeout leaves room for the cold path, and the
// budget for a couple of attempts of that length plus the waits between them.
const (
	defaultServiceTimeout = 30 * time.Second
	defaultMaxElapsedTime = 90 * time.Second
	maxQueryTries         = 8
	retryInitialInterval  = 2 * time.Second
	retryMaxInterval      = 30 * time.Second
)

// ErrUnresolved is the resolver answering without naming a source: the purl is one it
// is still working on, or one it has no source for at all. Both come back as a kind
// the SBOM cannot carry, and only time tells them apart.
var ErrUnresolved = errors.New("resolver reports no source")

// ErrTransport is a failure to obtain any answer at all — a refused connection, a
// request that outlived the client timeout. It never says anything about the package.
var ErrTransport = errors.New("resolver request failed")

type ServiceConfig struct {
	ServerURL string
	// Timeout bounds one request; MaxElapsedTime bounds the retries for one subject.
	Timeout        time.Duration
	MaxElapsedTime time.Duration
	HTTPClient     *http.Client
	Breaker        *ResolverBreaker
}

type Service struct {
	serverURL      string
	httpClient     *http.Client
	maxElapsedTime time.Duration
	breaker        *ResolverBreaker
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

	maxElapsedTime := cfg.MaxElapsedTime
	if maxElapsedTime <= 0 {
		maxElapsedTime = defaultMaxElapsedTime
	}

	return &Service{
		serverURL:      serverURL,
		httpClient:     httpClient,
		maxElapsedTime: maxElapsedTime,
		breaker:        cfg.Breaker,
	}
}

// Resolve waits out a cold resolution: an answer that names no source is retried
// within the budget, since the resolver reports one while its own lookup is still
// running and the build cannot use it either way.
func (s *Service) Resolve(ctx context.Context, purl string) (*ResolveResult, error) {
	u := fmt.Sprintf("%s/api/v1/resolve?purl=%s", s.serverURL, url.QueryEscape(purl))
	return s.query(ctx, u, "resolve", purl, true)
}

// CheckVCS asks the resolver to verify a repository URL the SBOM already carries,
// for instance the one a package manager recorded for its package. The resolver
// keys the answer by the URL alone, so the verdict does not depend on the purl
// that led to the link. An unconfirmed verdict is the caller's fallback signal rather
// than a failure, so it is not waited out the way a cold resolve is.
func (s *Service) CheckVCS(ctx context.Context, vcsURL string) (*ResolveResult, error) {
	u := fmt.Sprintf("%s/api/v1/vcs?url=%s", s.serverURL, url.QueryEscape(vcsURL))
	return s.query(ctx, u, "check vcs", vcsURL, false)
}

func (s *Service) query(ctx context.Context, u, op, subject string, requireSource bool) (*ResolveResult, error) {
	if err := s.breakerAllow(); err != nil {
		return nil, err
	}

	backOff := backoff.NewExponentialBackOff()
	backOff.InitialInterval = retryInitialInterval
	backOff.MaxInterval = retryMaxInterval

	var transportErr error
	res, err := backoff.Retry(ctx, func() (*ResolveResult, error) {
		res, err := s.doQuery(ctx, u, op)
		if err != nil {
			if errors.Is(err, ErrTransport) {
				transportErr = err
			}
			return nil, err
		}
		if requireSource && validateRefKind(res.Kind) != nil {
			return nil, s.classify(FailureClassContent, fmt.Errorf("%s: %w: kind %q, status %q", op, ErrUnresolved, res.Kind, res.Status))
		}
		return res, nil
	},
		backoff.WithBackOff(backOff),
		backoff.WithMaxTries(maxQueryTries),
		backoff.WithMaxElapsedTime(s.maxElapsedTime),
		backoff.WithNotify(func(err error, duration time.Duration) {
			logboek.Context(ctx).Warn().LogF(
				"WARNING: %s %q failed, retrying in %v: %s\n",
				op, subject, duration, err,
			)
		}),
	)
	// A context canceled between attempts or during the backoff wait comes back from
	// the retry loop as the bare cancellation cause, bypassing the classification
	// doQuery applies to a cancellation it observes itself.
	if err != nil && ctx.Err() != nil {
		return nil, &ClassifiedError{Class: FailureClassInfra, Err: fmt.Errorf("%s: %w", op, ctx.Err())}
	}

	// A resolution that never got through to the resolver failed on transport, whatever
	// the sourceless answer a later attempt was served: reporting the latter would blame
	// the package for an unreachable resolver and hide an infrastructure failure from the
	// breaker's caller.
	if errors.Is(err, ErrUnresolved) && transportErr != nil {
		return nil, transportErr
	}

	return res, err
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
		return nil, s.infraError(ctx, op, fmt.Errorf("%s: %w: %w", op, ErrTransport, err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, s.infraError(ctx, op, fmt.Errorf("%s: %w: read body: %w", op, ErrTransport, err))
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
