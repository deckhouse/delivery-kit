package e2e_attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/test/pkg/suite_init"
	"github.com/werf/werf/v2/test/pkg/werf"
)

var _ = Describe("Attestation lifecycle", Label("e2e", "attest", "lifecycle", "simple"), func() {
	DescribeTable("sign → get → verify → ls round-trip with VEX predicate",
		func(ctx SpecContext, containerBackendMode string) {
			setupAttestEnv(containerBackendMode)

			repoDirname := "repo_attest_lifecycle_" + containerBackendMode
			SuiteData.InitTestRepo(ctx, repoDirname, "simple")
			testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

			werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

			repo := suite_init.TestRepo(SuiteData.ProjectName)

			buildReportPath := filepath.Join(SuiteData.TmpDir, "attest_build_report_"+containerBackendMode+".json")
			werfProject.Build(ctx, &werf.BuildOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
				},
			})

			digest := readDigestFromReport(buildReportPath, "app")

			keys := generateTestKeyPair(SuiteData.TmpDir, "lifecycle-"+containerBackendMode)

			predicatePath := filepath.Join(SuiteData.TmpDir, "test.vex")
			writeVEXPredicate(predicatePath)

			werfProject.AttestSign(ctx, &werf.AttestSignOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--predicate", predicatePath,
						"--type", "openvex",
						"--sign-key", keys.KeyPath,
						"--repo", repo,
						"--digest", digest,
					},
				},
			})

			getOut := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "openvex",
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(getOut).To(ContainSubstring("CVE-2024-99999"))
			Expect(getOut).To(ContainSubstring("not_affected"))

			verifyOut := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--type", "openvex",
						"--key", keys.PubKeyPath,
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(verifyOut).To(ContainSubstring("CVE-2024-99999"))

			lsOut := werfProject.AttestLs(ctx, &werf.AttestLsOptions{
				CommonOptions: werf.CommonOptions{
					ExtraArgs: []string{
						"--repo", repo,
						"--digest", digest,
					},
				},
			})
			Expect(lsOut).To(ContainSubstring("openvex"))
			Expect(lsOut).To(ContainSubstring("yes"))
		},
		Entry("using Vanilla Docker", "vanilla-docker"),
		Entry("using BuildKit Docker", "buildkit-docker"),
	)

	It("attest verify fails with wrong key", Label("e2e", "attest", "negative", "simple"), func(ctx SpecContext) {
		setupAttestEnv("vanilla-docker")

		repoDirname := "repo_attest_verify_wrong_key"
		SuiteData.InitTestRepo(ctx, repoDirname, "simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

		repo := suite_init.TestRepo(SuiteData.ProjectName)

		buildReportPath := filepath.Join(SuiteData.TmpDir, "attest_wrong_key_report.json")
		werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
			},
		})
		digest := readDigestFromReport(buildReportPath, "app")

		signKeys := generateTestKeyPair(SuiteData.TmpDir, "wrong-key-sign")
		wrongKeys := generateTestKeyPair(SuiteData.TmpDir, "wrong-key-verify")

		predicatePath := filepath.Join(SuiteData.TmpDir, "wrong_key_test.vex")
		writeVEXPredicate(predicatePath)

		werfProject.AttestSign(ctx, &werf.AttestSignOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{
					"--predicate", predicatePath,
					"--type", "openvex",
					"--sign-key", signKeys.KeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})

		out := werfProject.AttestVerify(ctx, &werf.AttestVerifyOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--type", "openvex",
					"--key", wrongKeys.PubKeyPath,
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(out).To(ContainSubstring("signature verification failed"))
	})

	It("attest sign fails with missing predicate file", Label("e2e", "attest", "negative", "simple"), func(ctx SpecContext) {
		SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
		SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		repo := suite_init.TestRepo(SuiteData.ProjectName)

		keys := generateTestKeyPair(SuiteData.TmpDir, "missing-pred")

		out := werfProject.AttestSign(ctx, &werf.AttestSignOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--predicate", "/nonexistent/file.vex",
					"--type", "openvex",
					"--sign-key", keys.KeyPath,
					"--repo", repo,
					"--digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		})
		Expect(out).To(ContainSubstring("no such file"))
	})

	It("attest sign fails with unknown predicate type", Label("e2e", "attest", "negative", "simple"), func(ctx SpecContext) {
		SuiteData.Stubs.SetEnv("WERF_INSECURE_REGISTRY", "1")
		SuiteData.Stubs.SetEnv("WERF_SKIP_TLS_VERIFY_REGISTRY", "1")

		werfProject := werf.NewProject(SuiteData.WerfBinPath, SuiteData.TmpDir)
		repo := suite_init.TestRepo(SuiteData.ProjectName)

		keys := generateTestKeyPair(SuiteData.TmpDir, "unknown-type")

		predicatePath := filepath.Join(SuiteData.TmpDir, "unknown_type_test.vex")
		writeVEXPredicate(predicatePath)

		out := werfProject.AttestSign(ctx, &werf.AttestSignOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--predicate", predicatePath,
					"--type", "nonexistent-type",
					"--sign-key", keys.KeyPath,
					"--repo", repo,
					"--digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		})
		Expect(out).To(ContainSubstring("unknown predicate type"))
	})

	It("attest get fails when no attestation attached", Label("e2e", "attest", "negative", "simple"), func(ctx SpecContext) {
		setupAttestEnv("vanilla-docker")

		repoDirname := "repo_attest_get_missing"
		SuiteData.InitTestRepo(ctx, repoDirname, "simple")
		testRepoPath := SuiteData.GetTestRepoPath(repoDirname)

		werfProject := werf.NewProject(SuiteData.WerfBinPath, testRepoPath)

		repo := suite_init.TestRepo(SuiteData.ProjectName)

		buildReportPath := filepath.Join(SuiteData.TmpDir, "attest_get_missing_report.json")
		werfProject.Build(ctx, &werf.BuildOptions{
			CommonOptions: werf.CommonOptions{
				ExtraArgs: []string{"--save-build-report", "--build-report-path", buildReportPath},
			},
		})
		digest := readDigestFromReport(buildReportPath, "app")

		out := werfProject.AttestGet(ctx, &werf.AttestGetOptions{
			CommonOptions: werf.CommonOptions{
				ShouldFail: true,
				ExtraArgs: []string{
					"--type", "openvex",
					"--repo", repo,
					"--digest", digest,
				},
			},
		})
		Expect(out).To(ContainSubstring("not found"))
	})
})

type testKeyPair struct {
	KeyPath    string
	PubKeyPath string
}

func generateTestKeyPair(dir, suffix string) testKeyPair {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	keyPath := filepath.Join(dir, suffix+".key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	ExpectWithOffset(1, os.WriteFile(keyPath, keyPEM, 0o600)).To(Succeed())

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	pubKeyPath := filepath.Join(dir, suffix+".pub")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	ExpectWithOffset(1, os.WriteFile(pubKeyPath, pubPEM, 0o644)).To(Succeed())

	return testKeyPair{KeyPath: keyPath, PubKeyPath: pubKeyPath}
}

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

func writeVEXPredicate(path string) {
	vex := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/test-1",
  "author": "e2e-test",
  "timestamp": "2024-01-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": {"name": "CVE-2024-99999"},
      "products": [{"@id": "pkg:oci/test-image"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The vulnerable function is never called in this image."
    }
  ]
}`
	ExpectWithOffset(1, os.WriteFile(path, []byte(vex), 0o644)).To(Succeed())
}
