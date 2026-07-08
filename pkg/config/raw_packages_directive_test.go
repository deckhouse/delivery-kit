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
				Expect(packages[i].FileBased).To(Equal(expected.FileBased))
			}
		},

		Entry("os-pm with explicit workdir, spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type":    "os-pm",
						"workdir": "/app",
						"spec":    "my-pm.yaml",
						"lock":    "my-pm.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type:      PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{Workdir: "/app", Spec: "my-pm.yaml", Lock: "my-pm.lock"},
				},
			},
		),

		Entry("os-pm with workdir only (defaults for spec/lock)",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type":    "os-pm",
						"workdir": "/",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type:      PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{Workdir: "/", Spec: "pm.yaml", Lock: "pm.lock"},
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

		Entry("os-pm without workdir",
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
						"type": "unsupported-pm",
					},
				},
			},
		),
	)
})
