package testresource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

var active struct {
	sync.Mutex
	tracker *Tracker
}

type Snapshot struct {
	Backends       []string
	Repositories   []string
	DockerImageIDs []string
}

type Tracker struct {
	mu             sync.Mutex
	auditMu        sync.Mutex
	executable     string
	projectName    string
	snapshot       Snapshot
	api            client.APIClient
	cancel         context.CancelFunc
	done           chan struct{}
	auditDone      chan struct{}
	coveredThrough time.Time
	seenImageIDs   map[string]bool
	streamErr      error
	finished       bool
}

func Activate(_ context.Context, projectName, executable string) *Tracker {
	tracker := &Tracker{projectName: projectName, executable: executable, snapshot: Snapshot{Backends: []string{}}}
	active.Lock()
	defer active.Unlock()
	active.tracker = tracker
	return tracker
}

func ObserveCommand(ctx context.Context, executable string, args, environment []string) error {
	active.Lock()
	tracker := active.tracker
	active.Unlock()
	if tracker == nil {
		return nil
	}
	backend, repos := commandResources(tracker.executable, executable, args, environment)
	if backend == "" {
		return nil
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.finished {
		return errors.New("cannot start a command after resource tracking has finished")
	}
	tracker.snapshot.Backends = appendUnique(tracker.snapshot.Backends, backend)
	for _, repo := range repos {
		tracker.snapshot.Repositories = appendUnique(tracker.snapshot.Repositories, repo)
	}
	if backend == "docker" && tracker.api == nil {
		return tracker.startEvents(ctx)
	}
	return nil
}

func commandResources(werfExecutable, executable string, args, environment []string) (string, []string) {
	env := make(map[string]string)
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found {
			env[key] = value
		}
	}
	backend := ""
	if executable == werfExecutable {
		switch env["WERF_BUILDAH_MODE"] {
		case "", "docker":
			backend = "docker"
		case "native-rootless", "native-chroot", "auto", "default":
			backend = "buildah"
		}
	} else if len(args) > 0 {
		switch filepath.Base(executable) {
		case "docker":
			operation := args[0]
			if operation == "image" && len(args) > 1 {
				operation = args[1]
			}
			if slices.Contains([]string{"build", "buildx", "pull", "run", "create", "commit", "load", "import", "tag"}, operation) {
				backend = "docker"
			}
		case "buildah":
			backend = "buildah"
		}
	}
	var repos []string
	for key, value := range env {
		if key == "WERF_REPO" || key == "WERF_FINAL_REPO" || strings.HasPrefix(key, "WERF_SECONDARY_REPO") || strings.HasPrefix(key, "WERF_CACHE_REPO") {
			repos = append(repos, value)
		}
	}
	for index, arg := range args {
		key, value, assigned := strings.Cut(arg, "=")
		if !slices.Contains([]string{"--repo", "--final-repo", "--secondary-repo", "--cache-repo"}, key) {
			continue
		}
		if !assigned && index+1 < len(args) {
			value = args[index+1]
		}
		repos = append(repos, value)
	}
	return backend, repos
}

func (tracker *Tracker) startEvents(ctx context.Context) error {
	cli, err := command.NewDockerCli()
	if err != nil {
		return fmt.Errorf("create Docker event client: %w", err)
	}
	if err := cli.Initialize(flags.NewClientOptions()); err != nil {
		return fmt.Errorf("initialize Docker event client: %w", err)
	}
	tracker.api = cli.Client()
	tracker.coveredThrough = time.Now()
	eventCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	tracker.cancel = cancel
	timer := time.AfterFunc(10*time.Second, cancel)
	stream := tracker.api.Events(eventCtx, client.EventsListOptions{Since: tracker.coveredThrough.Format(time.RFC3339Nano)})
	timer.Stop()
	tracker.done = make(chan struct{})
	go func() {
		defer close(tracker.done)
		for {
			select {
			case event := <-stream.Messages:
				tracker.mu.Lock()
				tracker.record(event)
				tracker.mu.Unlock()
			case err := <-stream.Err:
				tracker.mu.Lock()
				tracker.recordStreamError(err, eventCtx.Err())
				tracker.mu.Unlock()
				return
			}
		}
	}()
	tracker.auditDone = make(chan struct{})
	go func() {
		defer close(tracker.auditDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-eventCtx.Done():
				return
			case <-ticker.C:
				auditCtx, cancelAudit := context.WithTimeout(eventCtx, 5*time.Second)
				err := tracker.replay(auditCtx, time.Now())
				cancelAudit()
				if err != nil {
					tracker.mu.Lock()
					tracker.recordStreamError(err, eventCtx.Err())
					tracker.mu.Unlock()
					return
				}
			}
		}
	}()
	if eventCtx.Err() != nil {
		return fmt.Errorf("start Docker event stream: %w", eventCtx.Err())
	}
	return nil
}

func (tracker *Tracker) record(event events.Message) {
	if owner, present := event.Actor.Attributes["werf"]; present && tracker.projectName != "" && owner != tracker.projectName {
		return
	}
	if event.Type == events.ImageEventType && event.Actor.ID != "" {
		if tracker.seenImageIDs == nil {
			tracker.seenImageIDs = make(map[string]bool)
		}
		if !tracker.seenImageIDs[event.Actor.ID] {
			tracker.seenImageIDs[event.Actor.ID] = true
			tracker.snapshot.DockerImageIDs = append(tracker.snapshot.DockerImageIDs, event.Actor.ID)
		}
	}
}

func (tracker *Tracker) replay(ctx context.Context, until time.Time) error {
	tracker.auditMu.Lock()
	defer tracker.auditMu.Unlock()
	tracker.mu.Lock()
	since := tracker.coveredThrough
	tracker.mu.Unlock()
	if !until.After(since) {
		return nil
	}
	stream := tracker.api.Events(ctx, client.EventsListOptions{Since: since.Format(time.RFC3339Nano), Until: until.Format(time.RFC3339Nano)})
	count := 0
	for {
		select {
		case event := <-stream.Messages:
			count++
			tracker.mu.Lock()
			tracker.record(event)
			tracker.mu.Unlock()
		case err := <-stream.Err:
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("read Docker event tail: %w", err)
			}
			if count >= 256 {
				return errors.New("Docker event tail reached history limit; image tracking may be incomplete")
			}
			tracker.mu.Lock()
			tracker.coveredThrough = until
			tracker.mu.Unlock()
			return nil
		}
	}
}

func (tracker *Tracker) recordStreamError(err, cancellation error) {
	if cancellation != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return
	}
	if err == nil {
		err = errors.New("stream closed without a result")
	}
	tracker.streamErr = fmt.Errorf("Docker event stream ended: %w", err)
}

func (tracker *Tracker) Finish(ctx context.Context) (Snapshot, error) {
	active.Lock()
	if active.tracker == tracker {
		active.tracker = nil
	}
	active.Unlock()
	tracker.mu.Lock()
	if tracker.finished {
		tracker.mu.Unlock()
		return Snapshot{}, errors.New("resource tracking has already finished")
	}
	tracker.finished = true
	api := tracker.api
	tracker.mu.Unlock()
	var finalErr error
	if api != nil {
		finalErr = tracker.replay(ctx, time.Now())
		tracker.cancel()
		select {
		case <-tracker.done:
		case <-ctx.Done():
			finalErr = errors.Join(finalErr, ctx.Err())
		}
		select {
		case <-tracker.auditDone:
		case <-ctx.Done():
			finalErr = errors.Join(finalErr, ctx.Err())
		}
		finalErr = errors.Join(finalErr, tracker.api.Close())
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.snapshot, errors.Join(finalErr, tracker.streamErr)
}

func appendUnique(values []string, value string) []string {
	if value != "" && !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}
