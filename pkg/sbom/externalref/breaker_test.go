package externalref

import (
	"errors"
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ResolverBreaker", func() {
	infraErr := func(i int) error {
		return &ClassifiedError{Class: FailureClassInfra, Err: fmt.Errorf("resolve %q: connection refused", fmt.Sprintf("pkg:npm/p%d@1.0.0", i))}
	}
	contentErr := func(i int) error {
		return &ClassifiedError{Class: FailureClassContent, Err: fmt.Errorf("resolve %q: unexpected status 404", fmt.Sprintf("pkg:npm/p%d@1.0.0", i))}
	}

	It("allows resolution while below the threshold", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold-1; i++ {
			Expect(breaker.Allow()).To(Succeed())
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		Expect(breaker.Allow()).To(Succeed())
	})

	It("trips after exactly threshold consecutive infrastructure failures", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}

		err := breaker.Allow()
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue())
		Expect(err.Error()).To(Equal("PURL resolver unavailable"), "Allow must not misattribute the endpoint and another PURL's last error to arbitrary components")
	})

	It("behaves identically when the threshold is reached on the final attempt of the build", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold-1; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		Expect(breaker.Allow()).To(Succeed())
		breaker.RecordFailure(FailureClassInfra, infraErr(resolverBreakerThreshold-1))
		Expect(errors.Is(breaker.Allow(), ErrResolverUnavailable)).To(BeTrue())
	})

	It("resets the counter on success", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold-1; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		breaker.RecordSuccess()
		for i := 0; i < resolverBreakerThreshold-1; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		Expect(breaker.Allow()).To(Succeed())

		breaker.RecordFailure(FailureClassInfra, infraErr(resolverBreakerThreshold))
		Expect(errors.Is(breaker.Allow(), ErrResolverUnavailable)).To(BeTrue())
	})

	It("ignores content failures", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold*3; i++ {
			breaker.RecordFailure(FailureClassContent, contentErr(i))
		}
		Expect(breaker.Allow()).To(Succeed())
	})

	It("does not let content failures reset an infrastructure failure streak", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold-1; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		breaker.RecordFailure(FailureClassContent, contentErr(0))
		breaker.RecordFailure(FailureClassInfra, infraErr(resolverBreakerThreshold))
		Expect(errors.Is(breaker.Allow(), ErrResolverUnavailable)).To(BeTrue())
	})

	It("latches once tripped", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		for i := 0; i < resolverBreakerThreshold; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}
		breaker.RecordSuccess()
		Expect(errors.Is(breaker.Allow(), ErrResolverUnavailable)).To(BeTrue())
	})

	It("exposes a canonical unavailable error only when tripped", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		Expect(breaker.UnavailableError()).To(Succeed())

		for i := 0; i < resolverBreakerThreshold; i++ {
			breaker.RecordFailure(FailureClassInfra, infraErr(i))
		}

		err := breaker.UnavailableError()
		Expect(errors.Is(err, ErrResolverUnavailable)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("https://refs.example.com"))
		Expect(err.Error()).To(ContainSubstring("connection refused"))
	})

	It("is safe under concurrent recording", func() {
		breaker := NewResolverBreaker("https://refs.example.com")
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				breaker.RecordFailure(FailureClassInfra, infraErr(i))
				_ = breaker.Allow()
			}(i)
		}
		wg.Wait()
		Expect(errors.Is(breaker.Allow(), ErrResolverUnavailable)).To(BeTrue())
	})
})
