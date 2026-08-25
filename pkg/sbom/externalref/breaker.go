package externalref

import (
	"errors"
	"fmt"
	"sync"
)

// ErrResolverUnavailable indicates that the external references resolver was declared
// unavailable for the remainder of the build after too many consecutive
// infrastructure-level failures.
var ErrResolverUnavailable = errors.New("PURL resolver unavailable")

const resolverBreakerThreshold = 5

// FailureClass classifies a single PURL resolution failure. Content failures are
// authoritative resolver answers (unknown package, invalid response) and keep the
// existing deferred aggregation behavior; infrastructure failures (unreachable or
// unhealthy resolver) count toward the resolver circuit breaker.
type FailureClass string

const (
	FailureClassContent FailureClass = "content"
	FailureClassInfra   FailureClass = "infra"
)

// ClassifiedError attaches a FailureClass to a resolution failure so that callers
// above the retry loop can distinguish content from infrastructure failures.
type ClassifiedError struct {
	Class FailureClass
	Err   error
}

func (e *ClassifiedError) Error() string {
	return e.Err.Error()
}

func (e *ClassifiedError) Unwrap() error {
	return e.Err
}

// ResolverBreaker is the process-wide availability state of the shared resolver
// endpoint: after resolverBreakerThreshold consecutive infrastructure failures the
// breaker trips (latched for the remainder of the build) and every subsequent
// resolution fails immediately with ErrResolverUnavailable.
type ResolverBreaker struct {
	endpoint string

	mu               sync.Mutex
	consecutiveInfra int
	lastInfraErr     error
	tripped          bool
}

func NewResolverBreaker(endpoint string) *ResolverBreaker {
	return &ResolverBreaker{endpoint: endpoint}
}

// Allow reports whether resolution may proceed; once the breaker is tripped it
// returns the canonical unavailable error.
func (b *ResolverBreaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripped {
		return b.unavailableErrorLocked()
	}
	return nil
}

func (b *ResolverBreaker) RecordFailure(class FailureClass, err error) {
	if class != FailureClassInfra {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastInfraErr = err
	b.consecutiveInfra++
	if b.consecutiveInfra >= resolverBreakerThreshold {
		b.tripped = true
	}
}

func (b *ResolverBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripped {
		return
	}
	b.consecutiveInfra = 0
}

// UnavailableError returns the canonical terminal error when the breaker is
// tripped and nil otherwise.
func (b *ResolverBreaker) UnavailableError() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.tripped {
		return nil
	}
	return b.unavailableErrorLocked()
}

func (b *ResolverBreaker) unavailableErrorLocked() error {
	return fmt.Errorf("%w at %s: %w", ErrResolverUnavailable, b.endpoint, b.lastInfraErr)
}
