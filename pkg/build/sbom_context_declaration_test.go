package build

import (
	"encoding/json"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
)

const validSBOMBuildContextDeclaration = `{
  "version": 1,
  "stages": {
    "install": {
      "subject": 1,
      "packages": [
        {
          "sourceImage": "kernel-headers-source-prep",
          "packageName": "kernel-headers-source",
          "packageVersion": "6.12",
          "packageType": "source",
          "sourcePlatform": "linux/amd64"
        },
        {
          "sourceImage": "glibc-source-prep",
          "packageName": "glibc-source",
          "packageVersion": "2.43",
          "packageType": "source",
          "sourcePlatform": "linux/amd64"
        }
      ]
    }
  }
}`

var _ = ginkgo.Describe("producer context declarations", func() {
	ginkgo.It("carries the declaration on a fixed label", func() {
		gomega.Expect(sbomBuildContextLabel).To(gomega.Equal("werf.io/sbom-build-context-v1"))
	})

	ginkgo.It("parses an explicit subject among several prepared sources", func() {
		declaration, err := parseSBOMBuildContextDeclaration([]byte(validSBOMBuildContextDeclaration))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(*declaration.Version).To(gomega.Equal(1))
		gomega.Expect(declaration.Stages).To(gomega.HaveLen(1))

		install, ok := declaration.Stages[stage.Install]
		gomega.Expect(ok).To(gomega.BeTrue())
		gomega.Expect(*install.Subject).To(gomega.Equal(1))
		gomega.Expect(install.Packages).To(gomega.HaveLen(2))
		gomega.Expect(install.Packages[0].SourceImage).To(gomega.Equal("kernel-headers-source-prep"))
		gomega.Expect(install.Packages[1]).To(gomega.Equal(sbomBuildContextPackage{
			SourceImage:    "glibc-source-prep",
			PackageName:    "glibc-source",
			PackageVersion: "2.43",
			PackageType:    "source",
			SourcePlatform: "linux/amd64",
		}))
	})

	ginkgo.It("accepts every allowed stage key", func() {
		for _, stageName := range []stage.StageName{stage.BeforeInstall, stage.Install, stage.BeforeSetup, stage.Setup} {
			data := []byte(`{"version":1,"stages":{"` + string(stageName) + `":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`)
			declaration, err := parseSBOMBuildContextDeclaration(data)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(stageName))
			gomega.Expect(declaration.Stages).To(gomega.HaveKey(stageName))
		}
	})

	ginkgo.It("ignores member order and whitespace but keeps package order and the subject index", func() {
		reordered := []byte(`{"stages":{"install":{"packages":[
			{"packageVersion":"6.12","sourcePlatform":"linux/amd64","packageType":"source","packageName":"kernel-headers-source","sourceImage":"kernel-headers-source-prep"},
			{"packageType":"source","packageName":"glibc-source","sourceImage":"glibc-source-prep","sourcePlatform":"linux/amd64","packageVersion":"2.43"}],
			"subject":1}},"version":1}`)

		canonical, err := parseSBOMBuildContextDeclaration([]byte(validSBOMBuildContextDeclaration))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		shuffled, err := parseSBOMBuildContextDeclaration(reordered)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		canonicalJSON, err := json.Marshal(canonical)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		shuffledJSON, err := json.Marshal(shuffled)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(shuffledJSON)).To(gomega.Equal(string(canonicalJSON)))

		swapped := []byte(`{"version":1,"stages":{"install":{"subject":0,"packages":[
			{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"},
			{"sourceImage":"kernel-headers-source-prep","packageName":"kernel-headers-source","packageVersion":"6.12","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`)
		swappedDeclaration, err := parseSBOMBuildContextDeclaration(swapped)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		swappedJSON, err := json.Marshal(swappedDeclaration)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(swappedJSON)).NotTo(gomega.Equal(string(canonicalJSON)))
	})

	// A bootstrap image may declare nothing but what it is: its own composition is
	// neither converged nor published.
	ginkgo.It("reads the declaration of a bootstrap image", func() {
		declaration, err := parseSBOMBuildContextDeclaration([]byte(`{"version":1,"bootstrap":true}`))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declaration.Bootstrap).To(gomega.BeTrue())
		gomega.Expect(declaration.Stages).To(gomega.BeEmpty())
	})

	// Its stages are still built like any other: the compilers running there are
	// instrumented ones that have to be told which prepared source they compile.
	ginkgo.It("reads the stages a bootstrap image declares", func() {
		declaration, err := parseSBOMBuildContextDeclaration([]byte(`{"version":1,"bootstrap":true,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"go-source-prep","packageName":"go-source","packageVersion":"1.27.3","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declaration.Bootstrap).To(gomega.BeTrue())
		gomega.Expect(declaration.Stages[stage.Install].Packages).To(gomega.HaveLen(1))
	})

	ginkgo.DescribeTable("rejects a declaration",
		func(data, message string) {
			declaration, err := parseSBOMBuildContextDeclaration([]byte(data))
			gomega.Expect(declaration).To(gomega.BeNil())
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(message)))
		},
		ginkgo.Entry("without data", "", "no data"),
		ginkgo.Entry("with whitespace only", "  \n\t", "no data"),
		ginkgo.Entry("with a null document", "null", "invalid: version is required"),
		ginkgo.Entry("with invalid UTF-8", "{\"version\":1,\"stages\":{\"install\":{\"subject\":0,\"packages\":[{\"sourceImage\":\"glibc\xff-prep\",\"packageName\":\"glibc-source\",\"packageVersion\":\"2.43\",\"packageType\":\"source\",\"sourcePlatform\":\"linux/amd64\"}]}}}", "not valid UTF-8"),
		ginkgo.Entry("with trailing JSON", validSBOMBuildContextDeclaration+` {"version":1}`, "invalid"),
		ginkgo.Entry("without a version", `{"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "invalid: version is required"),
		ginkgo.Entry("with a null version", `{"version":null,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "invalid: version is required"),
		ginkgo.Entry("with a future version", `{"version":2,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "unsupported version 2"),
		ginkgo.Entry("with a fractional version", `{"version":1.0,"stages":{}}`, "invalid"),
		ginkgo.Entry("without stages", `{"version":1}`, "at least one stage is required"),
		ginkgo.Entry("with null stages", `{"version":1,"stages":null}`, "at least one stage is required"),
		ginkgo.Entry("with empty stages", `{"version":1,"stages":{}}`, "at least one stage is required"),
		ginkgo.Entry("with a null bootstrap", `{"version":1,"bootstrap":null}`, "invalid"),
		ginkgo.Entry("with a stage that cannot carry a context", `{"version":1,"stages":{"beforeSetupX":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, `stage "beforeSetupX" is not allowed`),
		ginkgo.Entry("with a case-folded stage key", `{"version":1,"stages":{"Install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, `stage "Install" is not allowed`),
		ginkgo.Entry("with a duplicate stage key", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]},"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "duplicate"),
		ginkgo.Entry("with an unknown member", `{"version":1,"ownRoots":[],"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "unknown field"),
		ginkgo.Entry("with an unknown package member", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64","sourceDigest":"sha256:0"}]}}}`, "unknown field"),
		ginkgo.Entry("with a duplicate member", `{"version":1,"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "duplicate"),
		ginkgo.Entry("with a case-folded member", `{"Version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "unknown field"),
		ginkgo.Entry("with a case-folded package member", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"SourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "unknown field"),
		ginkgo.Entry("without a subject", `{"version":1,"stages":{"install":{"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "subject is required"),
		ginkgo.Entry("with a null subject", `{"version":1,"stages":{"install":{"subject":null,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "subject is required"),
		ginkgo.Entry("with a negative subject", `{"version":1,"stages":{"install":{"subject":-1,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "subject -1 is out of range"),
		ginkgo.Entry("with an out of range subject", `{"version":1,"stages":{"install":{"subject":1,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "subject 1 is out of range of 1 packages"),
		ginkgo.Entry("with a fractional subject", `{"version":1,"stages":{"install":{"subject":0.5,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "invalid"),
		ginkgo.Entry("without packages", `{"version":1,"stages":{"install":{"subject":0}}}`, "at least one package is required"),
		ginkgo.Entry("with null packages", `{"version":1,"stages":{"install":{"subject":0,"packages":null}}}`, "at least one package is required"),
		ginkgo.Entry("with empty packages", `{"version":1,"stages":{"install":{"subject":0,"packages":[]}}}`, "at least one package is required"),
		ginkgo.Entry("with an empty package field", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "package 0: packageName is required"),
		ginkgo.Entry("with a missing package field", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source"}]}}}`, "package 0: sourcePlatform is required"),
		ginkgo.Entry("with a padded package field", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":" glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "sourceImage \" glibc-source-prep\" has leading or trailing whitespace"),
		ginkgo.Entry("with a control character in a package field", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc\u0000prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"}]}}}`, "sourceImage contains control characters"),
		ginkgo.Entry("with a non-linux source platform", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"windows/amd64"}]}}}`, `sourcePlatform "windows/amd64" is not a canonical linux platform`),
		ginkgo.Entry("with an architecture-only source platform", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"amd64"}]}}}`, `sourcePlatform "amd64" is not a canonical linux platform`),
		ginkgo.Entry("with a padded source platform", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/ amd64"}]}}}`, `sourcePlatform "linux/ amd64" is not a canonical linux platform`),
		ginkgo.Entry("with an over-specified source platform", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/arm/v7/extra"}]}}}`, `sourcePlatform "linux/arm/v7/extra" is not a canonical linux platform`),
		ginkgo.Entry("with a duplicate source image handle", `{"version":1,"stages":{"install":{"subject":0,"packages":[{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"},{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/arm64"}]}}}`, `package 1: sourceImage "glibc-source-prep" is declared more than once`),
	)

	ginkgo.It("accepts the same package name and version from distinct sources", func() {
		data := []byte(`{"version":1,"stages":{"beforeInstall":{"subject":0,"packages":[
			{"sourceImage":"glibc-source-prep","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/amd64"},
			{"sourceImage":"glibc-source-prep-arm","packageName":"glibc-source","packageVersion":"2.43","packageType":"source","sourcePlatform":"linux/arm64/v8"}]}}}`)

		declaration, err := parseSBOMBuildContextDeclaration(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(declaration.Stages[stage.BeforeInstall].Packages).To(gomega.HaveLen(2))
	})
})
