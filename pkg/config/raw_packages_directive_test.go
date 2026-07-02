package config

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective", func() {
	var localGitRepo *LocalGitRepoStub
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		localGitRepo = NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
		giterminismManager = NewGiterminismManagerStub(localGitRepo)
	})

	DescribeTable("unmarshal and convert to directive succeed",
		func(yamlMap map[string]interface{}, expectedPackages []*PackagesDirective) {
			rawYaml, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			doc := &doc{Content: rawYaml}
			rawStapelImage := &rawStapelImage{doc: doc}

			Expect(yaml.UnmarshalStrict(doc.Content, rawStapelImage)).To(Succeed())

			meta := &Meta{}

			stapelImage, err := rawStapelImage.toStapelImageDirective(giterminismManager, meta, "image1")
			Expect(err).To(Succeed())

			Expect(stapelImage.Packages).To(HaveLen(len(expectedPackages)))
			for i, expected := range expectedPackages {
				Expect(stapelImage.Packages[i].Type).To(Equal(expected.Type))
				Expect(stapelImage.Packages[i].Spec.Packages).To(Equal(expected.Spec.Packages))
			}
		},

		Entry("os-pm with inline package list",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": []string{"curl", "openssl=3.3.7"},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					Spec: PackagesSpec{
						Packages: []string{"curl", "openssl=3.3.7"},
					},
				},
			},
		),

		Entry("packages section is optional (omitted)",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
			},
			[]*PackagesDirective{},
		),
	)

	DescribeTable("unmarshal fails with configError when required fields are missing",
		func(yamlMap map[string]interface{}) {
			rawYaml, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			doc := &doc{Content: rawYaml}
			rawStapelImage := &rawStapelImage{doc: doc}

			var errConf *configError
			err = yaml.UnmarshalStrict(doc.Content, rawStapelImage)
			Expect(errors.As(err, &errConf)).To(BeTrue())
		},

		Entry("packages entry without type",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"spec": "packages.txt",
					},
				},
			},
		),

		Entry("packages entry without spec",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails with configError for invalid content",
		func(yamlMap map[string]interface{}) {
			rawYaml, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			doc := &doc{Content: rawYaml}
			rawStapelImage := &rawStapelImage{doc: doc}

			Expect(yaml.UnmarshalStrict(doc.Content, rawStapelImage)).To(Succeed())

			meta := &Meta{}

			_, err = rawStapelImage.toStapelImageDirective(giterminismManager, meta, "image1")
			Expect(err).To(HaveOccurred())
		},

		Entry("packages entry with file spec",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "packages.txt",
					},
				},
			},
		),

		Entry("packages entry with unsupported type",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "go-mod",
						"spec": "packages.txt",
					},
				},
			},
		),

		Entry("packages entry with empty spec list",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": []string{},
					},
				},
			},
		),
	)
})

var _ = Describe("normalizePackages", func() {
	DescribeTable("flattening and deduplication",
		func(input []*PackagesDirective, expectedLen int, expectedPackages []string) {
			result := normalizePackages(input)

			if expectedLen == 0 {
				Expect(result).To(BeNil())
				return
			}

			Expect(result).To(HaveLen(expectedLen))
			Expect(result[0].Spec.Packages).To(Equal(expectedPackages))
		},

		Entry("returns nil for nil input",
			[]*PackagesDirective(nil),
			0,
			[]string(nil),
		),

		Entry("returns nil for empty slice",
			[]*PackagesDirective{},
			0,
			[]string(nil),
		),

		Entry("preserves single directive packages",
			[]*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
			},
			1,
			[]string{"curl", "jq"},
		),

		Entry("merges multiple directives",
			[]*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"jq"}}},
			},
			1,
			[]string{"curl", "jq"},
		),

		Entry("deduplicates across directives",
			[]*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
			},
			1,
			[]string{"curl", "jq"},
		),

		Entry("sorts packages deterministically",
			[]*PackagesDirective{
				{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"jq", "curl", "brotli"}}},
			},
			1,
			[]string{"brotli", "curl", "jq"},
		),
	)
})

var _ = Describe("rawPackagesDirective python smoke", func() {
	DescribeTable("canonical python type roundtrips through raw parser",
		func(yamlContent string, expectedType PackagesDirectiveType, expectedSpec string) {
			parentStack = util.NewStack()
			localGitRepo := NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
			giterminismManager := NewGiterminismManagerStub(localGitRepo)

			doc := &doc{Content: []byte(yamlContent)}
			rawStapelImage := &rawStapelImage{doc: doc}

			Expect(yaml.UnmarshalStrict(doc.Content, rawStapelImage)).To(Succeed())

			stapelImage, err := rawStapelImage.toStapelImageDirective(giterminismManager, &Meta{}, "image1")
			Expect(err).To(Succeed())
			Expect(stapelImage.Packages).To(HaveLen(1))
			Expect(stapelImage.Packages[0].Type).To(Equal(expectedType))
			Expect(stapelImage.Packages[0].FileBased.Spec).To(Equal(expectedSpec))
		},

		Entry("python-uv canonical",
			`image: image1
from: python:3.12
packages:
  - type: python-uv
    workdir: /app
`,
			PackagesDirectiveTypePythonUV,
			"pyproject.toml",
		),
	)
})
