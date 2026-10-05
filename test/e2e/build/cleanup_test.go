package e2e_build_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/buildah"
	"github.com/werf/werf/v3/test/pkg/contback"
	"github.com/werf/werf/v3/test/pkg/report"
	"github.com/werf/werf/v3/test/pkg/testresource"
	"github.com/werf/werf/v3/test/pkg/utils"
)

var _ = ginkgo.Describe("Test image cleanup", ginkgo.Label("e2e", "build", "extra"), func() {
	ginkgo.It("tracks a dangling image left by a command that fails", ginkgo.Label("docker"), func(ctx ginkgo.SpecContext) {
		setupEnv(setupEnvOptions{ContainerBackendMode: "docker"})
		tracker := testresource.Activate(ctx, SuiteData.ProjectName, "/bin/sh")
		imageRef := SuiteData.ProjectName + ":intermediate"
		idPath := filepath.Join(SuiteData.TmpDir, "first-image-id")
		var firstID string
		ginkgo.DeferCleanup(func(cleanupCtx ginkgo.SpecContext) {
			if firstID != "" {
				gomega.Expect(contback.CleanupProject(cleanupCtx, SuiteData.ProjectName, contback.CleanupProjectOptions{Backends: []string{"docker"}, DockerImageIDs: []string{firstID}})).To(gomega.Succeed())
			}
		}, ginkgo.NodeTimeout(time.Minute))
		ginkgo.DeferCleanup(func(cleanupCtx ginkgo.SpecContext) {
			resources, trackingErr := tracker.Finish(cleanupCtx)
			cleanupErr := contback.CleanupProject(cleanupCtx, SuiteData.ProjectName, contback.CleanupProjectOptions{
				Backends:       resources.Backends,
				Repositories:   resources.Repositories,
				DockerImageIDs: resources.DockerImageIDs,
			})
			gomega.Expect(trackingErr).NotTo(gomega.HaveOccurred())
			gomega.Expect(cleanupErr).NotTo(gomega.HaveOccurred())
			gomega.Expect(resources.DockerImageIDs).To(gomega.ContainElement(firstID))
			for _, ref := range []string{firstID, imageRef} {
				_, err := utils.RunCommand(cleanupCtx, "", "docker", "image", "inspect", ref)
				gomega.Expect(err).To(gomega.HaveOccurred())
			}
		}, ginkgo.NodeTimeout(2*time.Minute))
		replacement := SuiteData.ProjectName + ":replacement"
		script := fmt.Sprintf("printf 'FROM scratch\\n' | docker build --quiet --label werf=%q --label generation=first -t %q - && docker image inspect --format '{{.Id}}' %q > %q && printf 'FROM scratch\\n' | docker build --quiet --label werf=%q --label generation=second -t %q - && docker tag %q %q && exit 17", SuiteData.ProjectName, imageRef, imageRef, idPath, SuiteData.ProjectName, replacement, replacement, imageRef)
		_, err := utils.RunCommand(ctx, "", "/bin/sh", "-c", script)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("exit status 17")))
		first, err := os.ReadFile(idPath)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		firstID = strings.TrimSpace(string(first))
		dangling := utils.SucceedCommandOutputString(ctx, "", "docker", "image", "inspect", firstID, "--format", "{{len .RepoTags}}")
		gomega.Expect(strings.TrimSpace(dangling)).To(gomega.Equal("0"))
	})
	ginkgo.DescribeTable("removes project registry tags while retaining another project's alias", func(ctx ginkgo.SpecContext, opts setupEnvOptions) {
		contback.SkipIfUnavailable(opts.ContainerBackendMode)
		setupEnv(opts)
		backend := "docker"
		var commonArgs []string
		inspectArgs := []string{"image", "inspect"}
		if opts.ContainerBackendMode != "docker" {
			backend = "buildah"
			var err error
			commonArgs, err = buildah.GetBasicBuildahCliArgs(buildah.DefaultStorageDriver)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			inspectArgs = []string{"inspect", "--type", "image"}
		}
		SuiteData.InitTestRepo(ctx, "repo0", "simple/state0")
		project := report.NewProjectWithReport(newWerfProject("repo0"))
		_, buildReport := project.BuildWithReport(ctx, SuiteData.GetBuildReportPath("cleanup.json"), nil)
		imageRef := buildReport.Images["dockerfile"].DockerImageName
		registryRef := "localhost:65534/" + SuiteData.ProjectName + ":local-copy"
		foreignRepo := "localhost:65534/werf-test-neighbor-" + utils.GetRandomString(10)
		foreignRef := foreignRepo + ":keep"
		ginkgo.DeferCleanup(func(cleanupCtx ginkgo.SpecContext) {
			gomega.Expect(contback.CleanupProject(cleanupCtx, SuiteData.ProjectName, contback.CleanupProjectOptions{Repositories: []string{foreignRepo}})).To(gomega.Succeed())
		}, ginkgo.NodeTimeout(time.Minute))
		utils.RunSucceedCommand(ctx, "", backend, append(slices.Clone(commonArgs), "tag", imageRef, registryRef)...)
		utils.RunSucceedCommand(ctx, "", backend, append(slices.Clone(commonArgs), "tag", imageRef, foreignRef)...)
		for _, ref := range []string{imageRef, registryRef, foreignRef} {
			utils.RunSucceedCommand(ctx, "", backend, append(slices.Concat(commonArgs, inspectArgs), ref)...)
		}

		cleanupCtx, cancelCleanup := context.WithTimeout(ctx, 2*time.Minute)
		defer cancelCleanup()
		gomega.Expect(contback.CleanupProject(cleanupCtx, SuiteData.ProjectName, contback.CleanupProjectOptions{})).To(gomega.Succeed())
		for _, ref := range []string{imageRef, registryRef} {
			_, err := utils.RunCommand(ctx, "", backend, append(slices.Concat(commonArgs, inspectArgs), ref)...)
			gomega.Expect(err).To(gomega.HaveOccurred())
		}
		utils.RunSucceedCommand(ctx, "", backend, append(slices.Concat(commonArgs, inspectArgs), foreignRef)...)
	},
		backendEntry("using Docker", setupEnvOptions{ContainerBackendMode: "docker"}),
		backendEntry("using native rootless Buildah", setupEnvOptions{ContainerBackendMode: "native-rootless"}),
	)
})
