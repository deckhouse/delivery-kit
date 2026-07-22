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

	directivesFromYaml := func(yamlMap map[string]interface{}) ([]*PackagesDirective, error) {
		rawYaml, err := yaml.Marshal(yamlMap)
		Expect(err).To(Succeed())

		doc := &doc{Content: rawYaml}
		rawStapelImage := &rawStapelImage{doc: doc}

		Expect(yaml.UnmarshalStrict(doc.Content, rawStapelImage)).To(Succeed())

		stapelImage, err := rawStapelImage.toStapelImageDirective(giterminismManager, &Meta{}, "image1")
		if err != nil {
			return nil, err
		}
		return stapelImage.Packages, nil
	}

	DescribeTable("unmarshal and convert to directive succeed",
		func(yamlMap map[string]interface{}, expectedPackages []*PackagesDirective) {
			packages, err := directivesFromYaml(yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expectedPackages)))
			for i, expected := range expectedPackages {
				Expect(packages[i].Type).To(Equal(expected.Type))
				if packages[i].Type == PackagesDirectiveTypeOSPM {
					Expect(packages[i].Spec.Packages).To(Equal(expected.Spec.Packages))
				} else {
					Expect(packages[i].FileBased).To(Equal(expected.FileBased))
				}
			}
		},

		Entry("os-pm with inline spec list",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": []string{"curl", "jq"},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					Spec: PackagesSpec{Packages: []string{"curl", "jq"}},
				},
			},
		),

		Entry("os-pm with single package in spec",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": []string{"curl"},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					Spec: PackagesSpec{Packages: []string{"curl"}},
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
						"spec": "pm.yaml",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails for invalid content",
		func(yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("os-pm without packages",
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

		Entry("unsupported type",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type":    "unsupported-pm",
						"workdir": "/app",
						"spec":    "pm.yaml",
						"lock":    "pm.lock",
					},
				},
			},
		),
	)
})
