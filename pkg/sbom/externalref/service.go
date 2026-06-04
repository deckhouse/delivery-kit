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

	"github.com/werf/werf/v2/pkg/docker_registry/transport"
	"github.com/werf/werf/v2/pkg/werf"
)

type ServiceConfig struct {
	ServerURL  string
	Timeout    time.Duration
	HTTPClient *http.Client
}

type Service struct {
	serverURL  string
	httpClient *http.Client
}

func NewService(cfg ServiceConfig) *Service {
	serverURL := strings.TrimRight(cfg.ServerURL, "/")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: transport.NewTransport(
				werf.NewUserAgentTransport(http.DefaultTransport),
			),
			Timeout: timeout,
		}
	}

	return &Service{
		serverURL:  serverURL,
		httpClient: httpClient,
	}
}

func (s *Service) Resolve(ctx context.Context, purl string) (*ResolveResult, error) {
	u := fmt.Sprintf("%s/api/v1/resolve?purl=%s", s.serverURL, url.QueryEscape(purl))

	var lastErr error
	for i := 0; i < 3; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(i) * time.Second):
			}
		}

		result, err := s.doResolve(ctx, u, purl)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	return nil, lastErr
}

func (s *Service) doResolve(ctx context.Context, u, purl string) (*ResolveResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: create request: %w", purl, err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", purl, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: read body: %w", purl, err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("resolve %q: unexpected status %d: %s", purl, resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, err // retryable
		}
		return nil, err
	}

	var result ResolveResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("resolve %q: parse response: %w", purl, err)
	}

	if result.URL == "" {
		return nil, fmt.Errorf("resolve %q: %w", purl, ErrEmptyURL)
	}

	return &result, nil
}
