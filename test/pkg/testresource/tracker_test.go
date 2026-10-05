package testresource

import (
	"context"
	"testing"

	"github.com/moby/moby/api/types/events"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestResources(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Test resource tracking")
}

var _ = ginkgo.Describe("Resource tracking", func() {
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
