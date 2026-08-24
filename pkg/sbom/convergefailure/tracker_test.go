package convergefailure

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/logboek"
	"github.com/werf/werf/v2/pkg/sbom/externalref"
)

func newTrackerWithRecords(entries map[string]Record) *Tracker {
	tracker := NewTracker("https://refs.example.com")
	for name, record := range entries {
		tracker.failures.Store(name, record)
	}
	return tracker
}

var _ = Describe("Tracker.Classify", func() {
	It("defers enrich errors carrying ComponentError into the failure store", func() {
		tracker := NewTracker("https://refs.example.com")
		err := fmt.Errorf("enrich external references: %w", componentEnrichError("apk-tools"))

		Expect(tracker.Classify(err, "img1")).To(Succeed())

		value, found := tracker.failures.Load("img1")
		Expect(found).To(BeTrue())
		record := value.(Record)
		Expect(record.RootImage).To(Equal("img1"))
		Expect(record.Details).To(Equal("    - component: apk-tools: empty url\n"))
		Expect(record.RootCause).To(Equal("component: apk-tools: empty url"))
	})

	It("does not overwrite an existing record for the same image name (multiplatform)", func() {
		tracker := NewTracker("https://refs.example.com")
		first := fmt.Errorf("enrich external references: %w", componentEnrichError("apk-tools"))
		second := fmt.Errorf("enrich external references: %w", componentEnrichError("openssl"))

		Expect(tracker.Classify(first, "img1")).To(Succeed())
		Expect(tracker.Classify(second, "img1")).To(Succeed())

		value, _ := tracker.failures.Load("img1")
		Expect(value.(Record).Details).To(Equal("    - component: apk-tools: empty url\n"))
	})

	It("returns non-enrichment errors unchanged and records nothing", func() {
		tracker := NewTracker("https://refs.example.com")
		hardErr := errors.New("registry push failed")

		Expect(tracker.Classify(hardErr, "img1")).To(MatchError(hardErr))

		_, found := tracker.failures.Load("img1")
		Expect(found).To(BeFalse())
	})

	It("treats a breaker trip as terminal even when wrapped with the enrich sentinel", func() {
		tracker := NewTracker("https://refs.example.com")
		trippedErr := fmt.Errorf("enrich external references: %w", errors.Join(externalref.ErrResolverUnavailable, externalref.ErrExternalRefEnrich))

		err := tracker.Classify(trippedErr, "img1")
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, externalref.ErrResolverUnavailable)).To(BeTrue())

		_, found := tracker.failures.Load("img1")
		Expect(found).To(BeFalse(), "breaker trips must not be deferred into the failure store")
	})
})

var _ = Describe("Tracker.SkipDependent", func() {
	captureSkip := func(tracker *Tracker, imageName string, deps []ImageDependencies) (bool, string) {
		var output bytes.Buffer
		ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&output, &output))
		skipped := tracker.SkipDependent(ctx, imageName, deps)
		return skipped, output.String()
	}

	It("skips an image whose base image failed, warns with the real cause and records it", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {Details: "    - component: apk-tools: empty url\n", RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		skipped, output := captureSkip(tracker, "b", []ImageDependencies{{BaseImageName: "a"}})

		Expect(skipped).To(BeTrue())
		Expect(output).To(ContainSubstring(`WARNING: image b: SBOM converge skipped: SBOM for image "a" was not generated: component: apk-tools: empty url`))
		Expect(output).NotTo(ContainSubstring("rebuild it with SBOM generation enabled"))

		value, found := tracker.failures.Load("b")
		Expect(found).To(BeTrue())
		Expect(value.(Record).RootImage).To(Equal("a"))
	})

	It("skips an image whose import source failed", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"src-artifact": {Details: "    - component: apk-tools: empty url\n", RootImage: "src-artifact", RootCause: "component: apk-tools: empty url"},
		})

		skipped, output := captureSkip(tracker, "consumer", []ImageDependencies{{
			BaseImageName: "clean-base",
			Imports:       []ImportSource{{ImageName: "src-artifact"}},
		}})

		Expect(skipped).To(BeTrue())
		Expect(output).To(ContainSubstring(`SBOM for image "src-artifact" was not generated`))
	})

	It("propagates the root cause transitively across mixed base and import chains", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {Details: "    - component: apk-tools: empty url\n", RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		skippedB, _ := captureSkip(tracker, "b", []ImageDependencies{{BaseImageName: "a"}})
		Expect(skippedB).To(BeTrue())

		skippedC, output := captureSkip(tracker, "c", []ImageDependencies{{Imports: []ImportSource{{ImageName: "b"}}}})
		Expect(skippedC).To(BeTrue())
		Expect(output).To(ContainSubstring(`SBOM for image "a" was not generated`), "the root of the chain must be reported, not the intermediate skipped image")

		value, _ := tracker.failures.Load("c")
		Expect(value.(Record).RootImage).To(Equal("a"))
	})

	It("does not skip when no dependency failed and stays silent", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		skipped, output := captureSkip(tracker, "unrelated", []ImageDependencies{{
			BaseImageName: "clean-base",
			Imports:       []ImportSource{{ImageName: "other"}},
		}})

		Expect(skipped).To(BeFalse())
		Expect(output).To(BeEmpty())
		_, found := tracker.failures.Load("unrelated")
		Expect(found).To(BeFalse())
	})

	It("does not skip on an external import even when an image of that name failed", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"registry.example.com/foo:tag": {RootImage: "registry.example.com/foo:tag", RootCause: "component: apk-tools: empty url"},
		})

		skipped, _ := captureSkip(tracker, "consumer", []ImageDependencies{{
			Imports: []ImportSource{{ImageName: "registry.example.com/foo:tag", External: true}},
		}})

		Expect(skipped).To(BeFalse())
	})
})

var _ = Describe("Tracker.DependencyError", func() {
	It("reports the real cause for a dependency that failed enrichment in this run", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {Details: "    - component: apk-tools: empty url\n", RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		err, found := tracker.DependencyError("a")
		Expect(found).To(BeTrue())
		Expect(err.Error()).To(Equal(`SBOM for image "a" was not generated: component: apk-tools: empty url`))
		Expect(err.Error()).NotTo(ContainSubstring("rebuild it with SBOM generation enabled"))
	})

	It("reports the transitive root cause for a skipped dependency", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"b": {RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		err, found := tracker.DependencyError("b")
		Expect(found).To(BeTrue())
		Expect(err.Error()).To(Equal(`SBOM for image "a" was not generated: component: apk-tools: empty url`))
	})

	It("keeps the rebuild advice path for images not processed in this run", func() {
		tracker := NewTracker("https://refs.example.com")
		_, found := tracker.DependencyError("foreign")
		Expect(found).To(BeFalse())
	})

	It("does nothing for an empty name or a nil tracker", func() {
		tracker := newTrackerWithRecords(map[string]Record{"a": {RootImage: "a"}})
		_, found := tracker.DependencyError("")
		Expect(found).To(BeFalse())

		var nilTracker *Tracker
		_, found = nilTracker.DependencyError("a")
		Expect(found).To(BeFalse())
	})
})

var _ = Describe("Tracker.Finish", func() {
	finish := func(tracker *Tracker, totalImages int, convergeErr error) (error, string) {
		var output bytes.Buffer
		ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&output, &output))
		GinkgoT().Setenv(externalref.EnvName, "https://refs.example.com")
		err := tracker.Finish(ctx, totalImages, convergeErr)
		return err, output.String()
	}

	It("returns nothing and logs nothing on a clean run", func() {
		err, output := finish(NewTracker("https://refs.example.com"), 3, nil)
		Expect(err).To(Succeed())
		Expect(output).To(BeEmpty())
	})

	It("returns the aggregated report and the help hint when only enrichment failed", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {Details: "    - component: apk-tools: empty url\n", RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})

		err, output := finish(tracker, 2, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resolve external references: 1 of 2 images failed:"))
		Expect(output).To(ContainSubstring("External references resolution failed"))
	})

	It("emits the report and keeps the hard error terminal", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"a": {Details: "    - component: apk-tools: empty url\n", RootImage: "a", RootCause: "component: apk-tools: empty url"},
		})
		hardErr := errors.New("registry push failed")

		err, output := finish(tracker, 2, hardErr)
		Expect(err).To(MatchError(hardErr))
		Expect(output).To(ContainSubstring("resolve external references: 1 of 2 images failed:"), "the aggregated report must survive a hard error")
	})

	It("canonicalizes a wrapped breaker trip to exactly one resolver-unavailable error", func() {
		tracker := NewTracker("https://refs.example.com")
		tracker.breaker = trippedBreaker("https://refs.example.com")
		workerErr := fmt.Errorf("worker 3: %w", fmt.Errorf("enrich external references: %w", errors.Join(tracker.breaker.UnavailableError(), externalref.ErrExternalRefEnrich)))

		err, _ := finish(tracker, 2, workerErr)
		Expect(errors.Is(err, externalref.ErrResolverUnavailable)).To(BeTrue())
		Expect(strings.Count(err.Error(), "PURL resolver unavailable")).To(Equal(1))
		Expect(err.Error()).To(ContainSubstring("https://refs.example.com"))
	})
})

var _ = Describe("Tracker concurrency", func() {
	It("records failures and skips from parallel workers safely", func() {
		tracker := newTrackerWithRecords(map[string]Record{
			"root": {Details: "    - component: apk-tools: empty url\n", RootImage: "root", RootCause: "component: apk-tools: empty url"},
		})
		ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&bytes.Buffer{}, &bytes.Buffer{}))

		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				tracker.SkipDependent(ctx, fmt.Sprintf("dependent-%d", i), []ImageDependencies{{BaseImageName: "root"}})
				_, _ = tracker.DependencyError("root")
			}(i)
		}
		wg.Wait()

		err := tracker.AggregatedError(51)
		Expect(err.Error()).To(ContainSubstring("resolve external references: 51 of 51 images failed:"))
	})
})
