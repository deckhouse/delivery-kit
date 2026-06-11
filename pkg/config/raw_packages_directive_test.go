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
	It("returns nil for nil input", func() {
		result := normalizePackages(nil)
		Expect(result).To(BeNil())
	})

	It("returns nil for empty slice", func() {
		result := normalizePackages([]*PackagesDirective{})
		Expect(result).To(BeNil())
	})

	It("preserves single directive packages", func() {
		result := normalizePackages([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
		})
		Expect(result).To(HaveLen(1))
		Expect(result[0].Spec.Packages).To(Equal([]string{"curl", "jq"}))
	})

	It("merges multiple directives", func() {
		result := normalizePackages([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"jq"}}},
		})
		Expect(result).To(HaveLen(1))
		Expect(result[0].Spec.Packages).To(ConsistOf("curl", "jq"))
	})

	It("deduplicates across directives", func() {
		result := normalizePackages([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl", "jq"}}},
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"curl"}}},
		})
		Expect(result).To(HaveLen(1))
		Expect(result[0].Spec.Packages).To(ConsistOf("curl", "jq"))
	})

	It("sorts packages deterministically", func() {
		result := normalizePackages([]*PackagesDirective{
			{Type: PackagesDirectiveTypeOSPM, Spec: PackagesSpec{Packages: []string{"jq", "curl", "brotli"}}},
		})
		Expect(result[0].Spec.Packages).To(Equal([]string{"brotli", "curl", "jq"}))
	})
})
