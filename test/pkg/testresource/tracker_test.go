package testresource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/events"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image/journal"
)

func TestResources(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Test resource tracking")
}

var _ = ginkgo.Describe("Resource tracking", func() {
	ginkgo.It("persists event IDs and rejects uninstrumented native producers", func(ctx ginkgo.SpecContext) {
		directory := ginkgo.GinkgoT().TempDir()
		gomega.Expect(os.Mkdir(filepath.Join(directory, "docker"), 0o700)).To(gomega.Succeed())
		tracker := &Tracker{projectName: "werf-test-one", journalDir: directory}
		id := strings.Repeat("c", 64)
		tracker.record(events.Message{Type: events.ImageEventType, Actor: events.Actor{ID: id}})
		ids, err := journal.Read(ctx, filepath.Join(directory, "docker"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(ids).To(gomega.Equal([]string{id}))
		gomega.Expect(tracker.observeBuildahCommand(ctx, "buildah", []string{"--storage-driver", "vfs", "build", "."}, nil)).To(gomega.MatchError(gomega.ContainSubstring("not supported by image journaling")))
		gomega.Expect(tracker.observeBuildahCommand(ctx, "buildah", []string{"unshare", "buildah", "bud", "."}, nil)).To(gomega.HaveOccurred())
		gomega.Expect(tracker.observeBuildahCommand(ctx, "buildah", []string{"--root", "info", "bud", "."}, nil)).To(gomega.HaveOccurred())
		gomega.Expect(os.RemoveAll(filepath.Join(directory, "docker"))).To(gomega.Succeed())
		tracker.record(events.Message{Type: events.ImageEventType, Actor: events.Actor{ID: strings.Repeat("d", 64)}})
		gomega.Expect(tracker.streamErr).To(gomega.HaveOccurred())
	})
	ginkgo.It("keeps the producer guard after real Finish", func(ctx ginkgo.SpecContext) {
		tracker := Activate(ctx, "werf-test-one", "/bin/werf")
		_, err := tracker.Finish(ctx)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(ObserveCommand(ctx, "/bin/werf", []string{"build"}, []string{"WERF_BUILDAH_MODE=native-rootless"})).To(gomega.MatchError(gomega.ContainSubstring("finished")))
	})
	ginkgo.It("recognizes Docker producers after global options", func() {
		backend, _ := commandResources("/bin/werf", "docker", []string{"--debug", "--context", "build", "build", "."}, nil)
		gomega.Expect(backend).To(gomega.Equal("docker"))
		_, _, err := commandOperation("docker", []string{"--unknown", "build", "."})
		gomega.Expect(err).To(gomega.HaveOccurred())
	})
	ginkgo.DescribeTable("rejects alternate storage before admitting a command", func(executable string, args, extraEnv []string) {
		directory := ginkgo.GinkgoT().TempDir()
		ginkgo.GinkgoT().Setenv(journal.Env, directory)
		tracker := Activate(context.Background(), "werf-test-one", "/bin/werf")
		environment := append(os.Environ(), extraEnv...)
		gomega.Expect(ObserveCommand(context.Background(), executable, args, environment)).To(gomega.MatchError(gomega.ContainSubstring("not supported")))
		gomega.Expect(tracker.api).To(gomega.BeNil())
		_, err := tracker.Finish(context.Background())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	},
		ginkgo.Entry("Docker context", "docker", []string{"--context", "other", "build", "."}, []string{}),
		ginkgo.Entry("Docker host", "docker", []string{"--host=tcp://other:2375", "build", "."}, []string{}),
		ginkgo.Entry("Docker environment", "docker", []string{"build", "."}, []string{"DOCKER_HOST=tcp://other:2375"}),
		ginkgo.Entry("Buildah root", "buildah", []string{"--root", "/other", "tag", "source", "target"}, []string{}),
		ginkgo.Entry("Buildah driver", "buildah", []string{"--storage-driver=vfs", "tag", "source", "target"}, []string{}),
		ginkgo.Entry("journal override", "/bin/werf", []string{"build"}, []string{journal.Env + "=/other"}),
	)
	ginkgo.It("retains Finish errors for later cleanup attempts", func(ctx ginkgo.SpecContext) {
		tracker := Activate(ctx, "werf-test-one", "/bin/werf")
		trackingErr := errors.New("event tracking failed")
		tracker.streamErr = trackingErr
		_, err := tracker.Finish(ctx)
		gomega.Expect(errors.Is(err, trackingErr)).To(gomega.BeTrue())
		gomega.Expect(errors.Is(Flush(ctx), trackingErr)).To(gomega.BeTrue())
	})

	ginkgo.DescribeTable("identifies the backend from the effective command environment", func(mode, backend string) {
		actual, repos := commandResources("/bin/werf", "/bin/werf", []string{"build", "--repo", "registry/cli", "--final-repo=registry/final"}, []string{"WERF_BUILDAH_MODE=docker", "WERF_BUILDAH_MODE=" + mode, "WERF_REPO=registry/env"})
		gomega.Expect(actual).To(gomega.Equal(backend))
		gomega.Expect(repos).To(gomega.ConsistOf("registry/env", "registry/cli", "registry/final"))
	}, ginkgo.Entry("default Docker", "", "docker"), ginkgo.Entry("rootless Buildah", "native-rootless", "buildah"), ginkgo.Entry("chroot Buildah", "native-chroot", "buildah"))
	ginkgo.It("does not treat a Docker network query as a Docker image build", func() {
		backend, _ := commandResources("/bin/werf", "docker", []string{"network", "inspect", "bridge"}, nil)
		gomega.Expect(backend).To(gomega.BeEmpty())
	})
	ginkgo.It("does not connect to Docker for a Buildah-only spec", func() {
		tracker := Activate(context.Background(), "werf-test-one", "/bin/werf")
		gomega.Expect(ObserveCommand(context.Background(), "/bin/werf", []string{"build"}, []string{"WERF_BUILDAH_MODE=native-rootless"})).To(gomega.Succeed())
		snapshot, err := tracker.Finish(context.Background())
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(snapshot.Backends).To(gomega.Equal([]string{"buildah"}))
		gomega.Expect(tracker.api).To(gomega.BeNil())
	})
	ginkgo.It("retains image IDs even after untag events", func() {
		tracker := &Tracker{projectName: "werf-test-one"}
		tracker.record(events.Message{Type: events.ImageEventType, Action: "tag", Actor: events.Actor{ID: "owned"}, TimeNano: 1})
		tracker.record(events.Message{Type: events.ImageEventType, Actor: events.Actor{ID: "foreign", Attributes: map[string]string{"werf": "werf-test-other"}}})
		tracker.record(events.Message{Type: events.ImageEventType, Action: "untag", Actor: events.Actor{ID: "owned"}, TimeNano: 2})
		gomega.Expect(tracker.snapshot.DockerImageIDs).To(gomega.Equal([]string{"owned"}))
	})
})
