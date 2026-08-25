package e2e_vex_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/utils"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("VEX lifecycle", Label("e2e", "VEX", "lifecycle", "simple"), func() {
	DescribeTable("US1: publish VEX artifact during build",
		Label("publish"),
		func(ctx SpecContext, containerBackendMode string) {
			setupVexEnv(containerBackendMode)

			repoDirname := "repo_vex_publish_" + containerBackendMode
			SuiteData.InitTestRepo(ctx, repoDirname, "simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			buildReportPath := filepath.Join(SuiteData.TmpDir, "vex_build_report_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
				},
			})

			digest := readDigestFromReport(buildReportPath, "app")

			lsOut := werfProject.AttestLs(ctx, &werf.AttestLsOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(lsOut).To(ContainSubstring("openvex"))
			Expect(lsOut).To(ContainSubstring("no"))
		},
		Entry("using Vanilla Docker", "vanilla-docker"),
		Entry("using BuildKit Docker", "buildkit-docker"),
	)

	DescribeTable("US2: update VEX artifact, verify caching",
		Label("update"),
		func(ctx SpecContext, containerBackendMode string) {
			setupVexEnv(containerBackendMode)

			repoDirname := "repo_vex_update_" + containerBackendMode
			SuiteData.InitTestRepo(ctx, repoDirname, "simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			// ---- first build: publish initial VEX ----
			buildReportPath := filepath.Join(SuiteData.TmpDir, "vex_update_initial_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
				},
			})
			digest := readDigestFromReport(buildReportPath, "app")

			// verify initial VEX content via attest get
			getOut := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "openvex",
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(getOut).To(ContainSubstring("CVE-2024-E2E001"))
			Expect(getOut).To(ContainSubstring("not_affected"))

			// ---- update VEX document and rebuild ----
			vexPath := filepath.Join(testRepoPath, "vex.openvex.json")
			writeUpdatedVEX(vexPath, "CVE-2024-E2E002")
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "add", "vex.openvex.json")
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "commit", "-m", "update VEX document")

			buildReportPath2 := filepath.Join(SuiteData.TmpDir, "vex_update_second_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath2},
				},
			})
			digest2 := readDigestFromReport(buildReportPath2, "app")
			// digest should be the same since image content didn't change
			Expect(digest2).To(Equal(digest))

			// verify updated VEX content
			getOut2 := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "openvex",
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(getOut2).To(ContainSubstring("CVE-2024-E2E002"))
			Expect(getOut2).To(ContainSubstring("not_affected"))

			// ---- rebuild with no changes: should not fail and attestation should still be present ----
			buildReportPath3 := filepath.Join(SuiteData.TmpDir, "vex_update_third_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath3},
				},
			})
			digest3 := readDigestFromReport(buildReportPath3, "app")
			Expect(digest3).To(Equal(digest))

			// attestation must still be retrievable with updated content
			getOut3 := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "openvex",
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(getOut3).To(ContainSubstring("CVE-2024-E2E002"))
		},
		Entry("using Vanilla Docker", "vanilla-docker"),
		Entry("using BuildKit Docker", "buildkit-docker"),
	)

	DescribeTable("US3: cleanup orphaned VEX artifacts",
		Label("cleanup"),
		func(ctx SpecContext, containerBackendMode string) {
			setupVexEnv(containerBackendMode)

			repoDirname := "repo_vex_cleanup_" + containerBackendMode
			SuiteData.InitTestRepo(ctx, repoDirname, "simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			// werf cleanup requires a git remote origin.
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "init", "--bare", filepath.Join(testRepoPath, "remote.git"))
			utils.RunSucceedCommand(ctx, testRepoPath, "git", "remote", "add", "origin", filepath.Join(testRepoPath, "remote.git"))

			buildReportPath := filepath.Join(SuiteData.TmpDir, "vex_cleanup_report_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
				},
			})
			digest := readDigestFromReport(buildReportPath, "app")

			// confirm VEX artifact exists
			lsOut := werfProject.AttestLs(ctx, &werf.AttestLsOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(lsOut).To(ContainSubstring("openvex"))

			// remove the managed image reference to orphan the stage
			werfProject.RunCommand(ctx, []string{"managed-images", "rm", "app"}, werf.CommonOptions{
				ExtraArgs: []string{"--repo", repo},
			})

			// run cleanup — should remove orphaned stages and VEX artifacts
			werfProject.RunCommand(ctx, []string{"cleanup", "--repo", repo, "--without-kube"}, werf.CommonOptions{})

			// verify VEX artifact is removed — attest ls should fail
			werfProject.AttestLs(ctx, &werf.AttestLsOptions{
				CommonOptions: werf.CommonOptions{
					ShouldFail: true,
					ExtraArgs: []string{
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
		},
		Entry("using Vanilla Docker", "vanilla-docker"),
		Entry("using BuildKit Docker", "buildkit-docker"),
	)
})

func readDigestFromReport(reportPath, imageName string) string {
	data, err := os.ReadFile(reportPath)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	var report struct {
		Images map[string]struct {
			DockerImageDigest string `json:"DockerImageDigest"`
		} `json:"Images"`
	}
	ExpectWithOffset(1, json.Unmarshal(data, &report)).To(Succeed())

	imgInfo, ok := report.Images[imageName]
	ExpectWithOffset(1, ok).To(BeTrue(), "image %q not found in build report", imageName)
	ExpectWithOffset(1, imgInfo.DockerImageDigest).NotTo(BeEmpty(), "image %q has no digest in build report", imageName)

	return imgInfo.DockerImageDigest
}

func setupVexEnv(containerBackendMode string) {
	if strings.HasSuffix(containerBackendMode, "-docker") || containerBackendMode == "docker" {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", "docker")
	} else {
		SuiteData.Stubs.SetEnv("WERF_BUILDAH_MODE", containerBackendMode)
	}

	if containerBackendMode == "buildkit-docker" {
		SuiteData.Stubs.SetEnv("DOCKER_BUILDKIT", "1")
	} else {
		SuiteData.Stubs.UnsetEnv("DOCKER_BUILDKIT")
	}

	SuiteData.Stubs.SetEnv("WERF_REPO", suite_init.TestRepo(SuiteData.ProjectName))
	SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
	SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")
	SuiteData.Stubs.UnsetEnv("WERF_FORCE_STAGED_DOCKERFILE")
}

func writeUpdatedVEX(path, vulnID string) {
	vex := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/e2e-test-002",
  "author": "e2e-test",
  "timestamp": "2024-07-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": {"name": "` + vulnID + `"},
      "products": [{"@id": "pkg:oci/werf-test-app"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "This vulnerability is not reachable in this build."
    }
  ]
}`
	ExpectWithOffset(1, os.WriteFile(path, []byte(vex), 0o644)).To(Succeed())
}
