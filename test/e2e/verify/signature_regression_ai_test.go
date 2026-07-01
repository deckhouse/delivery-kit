package e2e_verify_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/report"
	"github.com/werf/werf/v2/test/pkg/werf"
)

// TestAI_ manifest-only signing regression.
//
// Signing must work when neither ELF signing nor dm-verity annotation is
// enabled. Those features append/rewrite image layers, which re-serializes the
// config blob and masked a bug where the manifest signature was computed over
// the pre-mutation manifest while a differently-serialized config was pushed.
// With only --sign-manifest there is no layer mutation, so the signed manifest
// must still match the pushed one, otherwise verification fails with
// "invalid signature when validating ASN.1 encoded signature".
var _ = Describe("Signature manifest-only regression", Label("e2e", "signature", "simple"), func() {
	DescribeTable("should sign and verify image manifest without ELF or dm-verity",
		func(ctx SpecContext, testOpts integrityTestOptions) {
			setupEnv(testOpts.setupEnvOptions)

			By("preparing test repo")
			repoDirname := "repo0"
			fixtureRelPath := "signature/inhouse/state"
			buildReportName := "report0.json"
			SuiteData.InitTestRepo(ctx, repoDirname, fixtureRelPath)

			By("building image with --sign-manifest only")
			werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.GetTestRepoPath(repoDirname))

			extraBuildArgs := []string{
				"--sign-manifest",
				"--sign-key", testKeyBase64,
				"--sign-cert", testCertBase64,
				"--sign-intermediates", testIntermediatesBase64,
			}

			reportProject := report.NewProjectWithReport(werfProject)
			buildOut, buildReport := reportProject.BuildWithReport(ctx, SuiteData.GetBuildReportPath(buildReportName), &werf.WithReportOptions{CommonOptions: werf.CommonOptions{ExtraArgs: extraBuildArgs}})
			Expect(buildOut).To(ContainSubstring("Building stage dockerfile/sign"))

			imageRef := buildReport.Images["dockerfile"].DockerImageName

			extraVerifyArgs := []string{
				"--image-ref", imageRef,
				"--verify-roots", testRootCertBase64,
				"--verify-manifest",
			}

			By("verifying image manifest signature")
			verifyOut := werfProject.Verify(ctx, &werf.VerifyOptions{CommonOptions: werf.CommonOptions{ExtraArgs: extraVerifyArgs}})
			Expect(verifyOut).To(ContainSubstring("Verifying image (1/1)"))
			Expect(verifyOut).To(ContainSubstring(fmt.Sprintf("Using reference: %s", imageRef)))
			Expect(verifyOut).To(ContainSubstring("Manifest signature ... ok"))
		},
		Entry("with repo using Vanilla Docker", integrityTestOptions{setupEnvOptions: setupEnvOptions{
			ContainerBackendMode:        "vanilla-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
		Entry("with local repo using BuildKit Docker", integrityTestOptions{setupEnvOptions{
			ContainerBackendMode:        "buildkit-docker",
			WithLocalRepo:               true,
			WithStagedDockerfileBuilder: false,
		}}),
	)
})
