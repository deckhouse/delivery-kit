// Package convergefailure owns the failure semantics of SBOM converge: which
// failures are deferred and which are terminal, which images count as "SBOM not
// generated in this run", how their dependents are found and skipped, and how the
// accumulated failures are reported to the user.
package convergefailure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/logboek/pkg/style"
	"github.com/werf/logboek/pkg/types"
	"github.com/werf/werf/v2/pkg/sbom/externalref"
)

// Record marks an image whose SBOM was not generated in this run. A direct
// enrichment failure has RootImage equal to the image's own name and carries
// component-level details; a skip record points at the root-cause image.
type Record struct {
	Details   string
	RootImage string
	RootCause string
}

// Tracker holds the failure state of a single SBOM converge run: the images whose
// SBOM was not generated and the availability state of the external references
// resolver. It is written by parallel converge workers and read by the code
// collecting base and import SBOMs, so all access goes through a sync.Map.
type Tracker struct {
	failures sync.Map
	breaker  *externalref.ResolverBreaker
}

func NewTracker(resolverEndpoint string) *Tracker {
	return &Tracker{breaker: externalref.NewResolverBreaker(resolverEndpoint)}
}

func (t *Tracker) Breaker() *externalref.ResolverBreaker {
	return t.breaker
}

// Classify decides what happens to a converge error: a resolver-unavailable trip
// and any non-enrichment error stay terminal, while an enrichment failure is
// recorded for the aggregated report and swallowed so the remaining images keep
// building. The breaker trip is checked first because the external references
// patcher wraps it with the enrichment sentinel as well.
func (t *Tracker) Classify(err error, imageName string) error {
	if errors.Is(err, externalref.ErrResolverUnavailable) {
		return err
	}

	if !errors.Is(err, externalref.ErrExternalRefEnrich) {
		return err
	}

	details := ""
	var compErr *externalref.ComponentError
	if errors.As(err, &compErr) {
		details = compErr.ComponentDetails()
	}
	t.failures.LoadOrStore(imageName, Record{
		Details:   details,
		RootImage: imageName,
		RootCause: compactCause(details),
	})
	return nil
}

// SkipDependent reports whether the image depends on an image whose SBOM was not
// generated in this run and, when it does, records the image as skipped with the
// root cause carried over, so chains of any depth report the originally failing
// image.
func (t *Tracker) SkipDependent(ctx context.Context, imageName string, deps []ImageDependencies) bool {
	record, found := t.recordForDependencies(DependencyImageNames(deps))
	if !found {
		return false
	}

	t.failures.LoadOrStore(imageName, Record{
		RootImage: record.RootImage,
		RootCause: record.RootCause,
	})
	logboek.Context(ctx).Warn().LogF("WARNING: image %s: SBOM converge skipped: SBOM for image %q was not generated: %s\n", imageName, record.RootImage, record.RootCause)

	return true
}

// DependencyError returns the reason a dependency's SBOM is unavailable when that
// dependency was processed by this run. Callers use it to report the real cause
// instead of advising a rebuild of an image that was just built with SBOM enabled.
func (t *Tracker) DependencyError(dependencyName string) (error, bool) {
	if t == nil || dependencyName == "" {
		return nil, false
	}
	value, found := t.failures.Load(dependencyName)
	if !found {
		return nil, false
	}
	record := value.(Record)
	return fmt.Errorf("SBOM for image %q was not generated: %s", record.RootImage, record.RootCause), true
}

// Finish closes a converge run: the aggregated report is emitted on every exit
// path, and a terminal error keeps its place as the error the build fails with.
func (t *Tracker) Finish(ctx context.Context, totalImages int, convergeErr error) error {
	aggErr := t.AggregatedError(totalImages)

	if convergeErr != nil {
		if aggErr != nil {
			logboek.Context(ctx).Warn().LogF("%s\n", aggErr)
			LogResolverHelpHint(ctx)
		}
		return t.terminalError(convergeErr)
	}

	if aggErr != nil {
		LogResolverHelpHint(ctx)
		return aggErr
	}

	return nil
}

func (t *Tracker) recordForDependencies(dependencyNames []string) (Record, bool) {
	for _, dependencyName := range dependencyNames {
		if dependencyName == "" {
			continue
		}
		if value, found := t.failures.Load(dependencyName); found {
			return value.(Record), true
		}
	}
	return Record{}, false
}

// terminalError replaces a worker-wrapped breaker trip with the breaker's own
// error so exactly one resolver-unavailable error surfaces per build.
func (t *Tracker) terminalError(err error) error {
	if !errors.Is(err, externalref.ErrResolverUnavailable) {
		return err
	}
	if canonical := t.breaker.UnavailableError(); canonical != nil {
		return canonical
	}
	return err
}

func compactCause(details string) string {
	lines := lo.Filter(strings.Split(details, "\n"), func(line string, _ int) bool {
		return strings.TrimSpace(line) != ""
	})
	if len(lines) == 0 {
		return "external references enrichment failed"
	}
	cause := strings.TrimPrefix(strings.TrimSpace(lines[0]), "- ")
	if len(lines) > 1 {
		cause = fmt.Sprintf("%s (and %d more component errors)", cause, len(lines)-1)
	}
	return cause
}

// LogResolverHelpHint prominently tells the user where to get help with external
// references resolution errors.
func LogResolverHelpHint(ctx context.Context) {
	serverURL := os.Getenv(externalref.EnvName)
	if serverURL == "" {
		return
	}

	logboek.Context(ctx).Warn().LogBlock("External references resolution failed").
		Options(func(options types.LogBlockOptionsInterface) {
			options.Style(style.Highlight())
		}).
		Do(func() {
			logboek.Context(ctx).Warn().LogF("Some package URLs could not be resolved by the external references service.\n")
			logboek.Context(ctx).Warn().LogF("See %s/help for details on resolving these errors.\n", strings.TrimRight(serverURL, "/"))
		})
}
