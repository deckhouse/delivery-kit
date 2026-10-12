package testresource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/opencontainers/go-digest"

	"github.com/werf/werf/v3/pkg/buildah"
	"github.com/werf/werf/v3/pkg/image/journal"
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
	resolvedEvents map[string]string
	streamErr      error
	finished       bool
	journalDir     string
}

func Activate(_ context.Context, projectName, executable string) *Tracker {
	tracker := &Tracker{projectName: projectName, executable: executable, snapshot: Snapshot{Backends: []string{}}, journalDir: os.Getenv(journal.Env)}
	active.Lock()
	defer active.Unlock()
	active.tracker = tracker
	return tracker
}

func ObserveCommand(ctx context.Context, executable string, args, environment []string) error {
	return observeCommand(ctx, executable, args, environment, false)
}

func PrepareCommand(ctx context.Context, executable string, args, environment []string) (func(error, []byte) error, error) {
	if err := observeCommand(ctx, executable, args, environment, true); err != nil {
		return nil, err
	}
	active.Lock()
	tracker := active.tracker
	active.Unlock()
	if tracker == nil || tracker.journalDir == "" || filepath.Base(executable) != "buildah" {
		return func(error, []byte) error { return nil }, nil
	}
	operation, index, err := commandOperation(executable, args)
	if err != nil {
		return nil, err
	}
	if operation != "pull" && operation != "from" {
		return func(error, []byte) error { return nil }, nil
	}
	kind, ref, err := buildahPreparationResult(operation, args[index+1:])
	if err != nil {
		return nil, err
	}
	finish, err := journal.Begin(ctx, tracker.journalDir)
	if err != nil {
		return nil, err
	}
	return func(commandErr error, stdout []byte) error {
		if operation == "pull" && commandErr == nil {
			fields := strings.Fields(string(stdout))
			if len(fields) == 0 {
				return fmt.Errorf("buildah pull returned no image ID")
			}
			ref = strings.TrimPrefix(fields[len(fields)-1], "sha256:")
			if err := digest.Digest("sha256:" + ref).Validate(); err != nil {
				return fmt.Errorf("invalid buildah pull result ID: %w", err)
			}
		}
		inspectCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(inspectCtx, executable, append(slices.Clone(args[:index]), "inspect", "--type", kind, ref)...)
		command.Env = environment
		output, err := command.Output()
		if err != nil {
			return fmt.Errorf("inspect buildah %s result %q: %w", operation, ref, err)
		}
		var inspected struct{ FromImageID string }
		if err := json.Unmarshal(output, &inspected); err != nil {
			return fmt.Errorf("decode buildah %s result: %w", operation, err)
		}
		if operation == "pull" && commandErr == nil && strings.TrimPrefix(inspected.FromImageID, "sha256:") != ref {
			return fmt.Errorf("buildah pull result ID differs from inspected image")
		}
		if err := journal.Record(inspectCtx, filepath.Join(tracker.journalDir, "buildah"), inspected.FromImageID); err != nil {
			return fmt.Errorf("record buildah %s result: %w", operation, err)
		}
		if commandErr != nil {
			return fmt.Errorf("buildah %s failed; image journal may be incomplete: %w", operation, commandErr)
		}
		return finish()
	}, nil
}

func buildahPreparationResult(operation string, args []string) (string, string, error) {
	var source, container string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "-") {
			if source != "" {
				return "", "", fmt.Errorf("buildah %s image tracking requires one image reference", operation)
			}
			source = arg
			continue
		}
		name, value, assigned := strings.Cut(arg, "=")
		if name == "--tls-verify" && assigned && (value == "true" || value == "false") {
			continue
		}
		if operation == "from" && slices.Contains([]string{"--name", "--isolation", "--format"}, name) {
			if !assigned {
				index++
				if index >= len(args) {
					return "", "", fmt.Errorf("missing value for buildah %s", name)
				}
				value = args[index]
			}
			if name == "--name" {
				container = value
			}
			continue
		}
		return "", "", fmt.Errorf("buildah %s option %q is not supported by image tracking", operation, arg)
	}
	if source == "" || (operation == "from" && container == "") {
		return "", "", fmt.Errorf("buildah %s requires an explicit result reference for image tracking", operation)
	}
	if operation == "from" {
		return "container", container, nil
	}
	return "image", source, nil
}

func observeCommand(ctx context.Context, executable string, args, environment []string, trackPreparation bool) error {
	active.Lock()
	tracker := active.tracker
	active.Unlock()
	if tracker == nil {
		return nil
	}
	if tracker.journalDir != "" && executable != tracker.executable && slices.Contains([]string{"docker", "buildah"}, filepath.Base(executable)) {
		if _, _, err := commandOperation(executable, args); err != nil {
			return err
		}
	}
	backend, repos := commandResources(tracker.executable, executable, args, environment)
	if backend == "" {
		return nil
	}
	if tracker.journalDir != "" {
		if err := tracker.validateCommandStorage(executable, args, environment, backend); err != nil {
			return err
		}
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.finished {
		return errors.New("cannot start a command after resource tracking has finished")
	}
	if tracker.journalDir != "" && backend == "buildah" && executable != tracker.executable {
		operation, _, err := commandOperation(executable, args)
		if err != nil {
			return err
		}
		if !trackPreparation || (operation != "pull" && operation != "from") {
			if err := tracker.observeBuildahCommand(ctx, executable, args, environment); err != nil {
				return err
			}
		}
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

func (tracker *Tracker) validateCommandStorage(executable string, args, environment []string, backend string) error {
	env := make(map[string]string)
	for _, entry := range environment {
		if key, value, found := strings.Cut(entry, "="); found {
			env[key] = value
		}
	}
	if env[journal.Env] != tracker.journalDir {
		return fmt.Errorf("image journal override is not supported during resource tracking")
	}
	if backend == "docker" {
		for _, name := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
			if env[name] != os.Getenv(name) {
				return fmt.Errorf("%s override is not supported during image tracking", name)
			}
		}
	} else if driver := env["WERF_BUILDAH_STORAGE_DRIVER"]; driver != "" && driver != string(buildah.DefaultStorageDriver) {
		return fmt.Errorf("alternate Buildah storage driver is not supported during image tracking")
	}
	if executable == tracker.executable {
		return nil
	}
	_, operationIndex, err := commandOperation(executable, args)
	if err != nil {
		return err
	}
	for index := 0; index < operationIndex; index++ {
		name, value, assigned := strings.Cut(args[index], "=")
		if backend == "docker" && slices.Contains([]string{"--host", "-H", "--context", "-c", "--config", "--tls", "--tlsverify", "--tlscacert", "--tlscert", "--tlskey"}, name) {
			return fmt.Errorf("Docker endpoint option %s is not supported during image tracking", name)
		}
		if backend == "buildah" && slices.Contains([]string{"--root", "--runroot"}, name) {
			return fmt.Errorf("Buildah storage option %s is not supported during image tracking", name)
		}
		if backend == "buildah" && name == "--storage-driver" {
			if !assigned {
				value = args[index+1]
			}
			if value != string(buildah.DefaultStorageDriver) {
				return fmt.Errorf("alternate Buildah storage driver is not supported during image tracking")
			}
		}
	}
	return nil
}

func (tracker *Tracker) observeBuildahCommand(ctx context.Context, executable string, args, environment []string) error {
	arg, index, err := commandOperation(executable, args)
	if err != nil {
		return err
	}
	switch arg {
	case "build", "bud", "commit", "pull", "load", "import", "from", "manifest", "unshare":
		return fmt.Errorf("direct buildah %s is not supported by image journaling; use the instrumented werf backend", arg)
	case "tag":
		if index+1 >= len(args) {
			return fmt.Errorf("buildah tag source is missing")
		}
		command := exec.CommandContext(ctx, executable, append(slices.Clone(args[:index]), "inspect", "--type", "image", args[index+1])...)
		command.Env = environment
		output, err := command.Output()
		if err != nil {
			return fmt.Errorf("inspect buildah tag source: %w", err)
		}
		var image struct{ FromImageID string }
		if err := json.Unmarshal(output, &image); err != nil {
			return fmt.Errorf("decode buildah tag source: %w", err)
		}
		return journal.Record(ctx, filepath.Join(tracker.journalDir, "buildah"), image.FromImageID)
	case "inspect", "images", "containers", "rmi", "rm", "run", "mount", "umount", "info", "version", "push":
		return nil
	}
	return fmt.Errorf("unrecognized direct buildah operation with image journaling")
}

func commandOperation(executable string, args []string) (string, int, error) {
	valueFlags := []string{"--config", "--context", "-c", "--host", "-H", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey"}
	boolFlags := []string{"--debug", "-D", "--tls", "--tlsverify"}
	if filepath.Base(executable) == "buildah" {
		valueFlags = []string{"--root", "--runroot", "--storage-driver", "--storage-opt", "--registries-conf", "--registries-conf-dir", "--signature-policy", "--log-level", "--userns-uid-map", "--userns-gid-map", "--cgroup-manager"}
		boolFlags = []string{"--debug"}
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if !strings.HasPrefix(arg, "-") {
			return arg, index, nil
		}
		name, _, assigned := strings.Cut(arg, "=")
		if slices.Contains(boolFlags, name) {
			continue
		}
		if slices.Contains(valueFlags, name) {
			if !assigned {
				index++
				if index >= len(args) {
					return "", 0, fmt.Errorf("missing value for %s", name)
				}
			}
			continue
		}
		return "", 0, fmt.Errorf("unsupported %s global option %q with image tracking", filepath.Base(executable), arg)
	}
	return "", 0, nil
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
			operation, index, err := commandOperation(executable, args)
			if err != nil {
				return "", nil
			}
			if operation == "image" && len(args) > index+1 {
				operation = args[index+1]
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
				tracker.record(event)
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
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if owner, present := event.Actor.Attributes["werf"]; present && tracker.projectName != "" && owner != tracker.projectName {
		return
	}
	if event.Type == events.ImageEventType && event.Actor.ID != "" {
		id := event.Actor.ID
		if tracker.journalDir != "" {
			id = strings.TrimPrefix(id, "sha256:")
			if err := digest.Digest("sha256:" + id).Validate(); err != nil {
				key := fmt.Sprintf("%s/%s/%d/%d", event.Actor.ID, event.Action, event.Time, event.TimeNano)
				if resolved := tracker.resolvedEvents[key]; resolved != "" && (event.Time != 0 || event.TimeNano != 0) {
					id = resolved
				} else {
					api := tracker.api
					tracker.mu.Unlock()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					inspected, err := api.ImageInspect(ctx, event.Actor.ID)
					cancel()
					tracker.mu.Lock()
					if resolved := tracker.resolvedEvents[key]; resolved != "" && (event.Time != 0 || event.TimeNano != 0) {
						id = resolved
					} else if err != nil {
						tracker.streamErr = errors.Join(tracker.streamErr, fmt.Errorf("resolve Docker event reference %q: %w", event.Actor.ID, err))
						return
					} else {
						id = strings.TrimPrefix(inspected.ID, "sha256:")
						if tracker.resolvedEvents == nil {
							tracker.resolvedEvents = make(map[string]string)
						}
						tracker.resolvedEvents[key] = id
					}
				}
			}
		}
		if tracker.seenImageIDs == nil {
			tracker.seenImageIDs = make(map[string]bool)
		}
		if !tracker.seenImageIDs[id] {
			if tracker.journalDir != "" {
				if err := journal.Record(context.Background(), filepath.Join(tracker.journalDir, "docker"), id); err != nil {
					tracker.streamErr = errors.Join(tracker.streamErr, fmt.Errorf("record Docker event: %w", err))
				}
			}
			tracker.seenImageIDs[id] = true
			tracker.snapshot.DockerImageIDs = append(tracker.snapshot.DockerImageIDs, id)
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
			tracker.record(event)
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
	tracker.streamErr = errors.Join(tracker.streamErr, fmt.Errorf("Docker event stream ended: %w", err))
}

func Flush(ctx context.Context) error {
	active.Lock()
	tracker := active.tracker
	active.Unlock()
	if tracker == nil {
		return nil
	}
	tracker.mu.Lock()
	if tracker.finished {
		err := tracker.streamErr
		tracker.mu.Unlock()
		return err
	}
	api := tracker.api
	tracker.mu.Unlock()
	if api == nil {
		return nil
	}
	err := tracker.replay(ctx, time.Now())
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return errors.Join(err, tracker.streamErr)
}

func (tracker *Tracker) Finish(ctx context.Context) (Snapshot, error) {
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
	tracker.streamErr = errors.Join(finalErr, tracker.streamErr)
	return tracker.snapshot, tracker.streamErr
}

func appendUnique(values []string, value string) []string {
	if value != "" && !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}
