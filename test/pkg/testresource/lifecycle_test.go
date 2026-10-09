package testresource

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Event tracking lifecycle", func() {
	ginkgo.It("does not advance verified coverage just because a newer live event arrived", func() {
		start := time.Unix(100, 0)
		api := &eventHistoryStub{count: 1}
		tracker := &Tracker{api: api, coveredThrough: start}
		tracker.record(events.Message{Type: events.ImageEventType, Actor: events.Actor{ID: "newer"}, TimeNano: start.Add(time.Second).UnixNano()})
		gomega.Expect(tracker.coveredThrough).To(gomega.Equal(start))
		gomega.Expect(tracker.replay(context.Background(), start.Add(2*time.Second))).To(gomega.Succeed())
		gomega.Expect(api.since).To(gomega.Equal(start.Format(time.RFC3339Nano)))
		gomega.Expect(tracker.snapshot.DockerImageIDs).To(gomega.ContainElement("replayed-image"))
	})
	ginkgo.It("fails closed when replay reaches the Docker history limit", func() {
		start := time.Unix(100, 0)
		tracker := &Tracker{api: &eventHistoryStub{count: 256}, coveredThrough: start}
		gomega.Expect(tracker.replay(context.Background(), start.Add(time.Second))).To(gomega.MatchError(gomega.ContainSubstring("history limit")))
		gomega.Expect(tracker.coveredThrough).To(gomega.Equal(start))
	})
	ginkgo.It("rejects a late command registration on a finished tracker", func() {
		tracker := Activate(context.Background(), "werf-test-one", "/bin/werf")
		tracker.finished = true
		defer func() { active.Lock(); active.tracker = nil; active.Unlock() }()
		gomega.Expect(ObserveCommand(context.Background(), "/bin/werf", []string{"build"}, []string{"WERF_BUILDAH_MODE=native-rootless"})).To(gomega.MatchError(gomega.ContainSubstring("finished")))
		gomega.Expect(tracker.snapshot.Backends).To(gomega.BeEmpty())
	})
	ginkgo.It("preserves a stream EOF even if cancellation happened before it was handled", func() {
		tracker := &Tracker{}
		tracker.recordStreamError(io.EOF, context.Canceled)
		gomega.Expect(errors.Is(tracker.streamErr, io.EOF)).To(gomega.BeTrue())
	})
	ginkgo.It("does not report its own stream cancellation as an error", func() {
		tracker := &Tracker{}
		tracker.recordStreamError(context.Canceled, context.Canceled)
		gomega.Expect(tracker.streamErr).NotTo(gomega.HaveOccurred())
	})
	ginkgo.It("recognizes Docker image subcommands independently of the werf backend", func() {
		backend, _ := commandResources("/bin/werf", "docker", []string{"image", "pull", "example/image"}, []string{"WERF_BUILDAH_MODE=native-rootless"})
		gomega.Expect(backend).To(gomega.Equal("docker"))
	})
})
