package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective go-mod", func() {
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

	DescribeTable("unmarshal and convert succeed",
		func(yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].GoMod).To(Equal(exp.GoMod))
			}
		},

		Entry("go-mod with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "golang:1.23-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "go-mod",
						"workdir": "/app/api",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeGoMod,
					GoMod: GoModSpec{
						Workdir: "/app/api",
						Spec:    "go.mod",
						Lock:    "go.sum",
					},
				},
			},
		),

		Entry("go-mod with explicit spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "golang:1.23-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "go-mod",
						"workdir": "/app/cli",
						"spec":    "go.mod",
						"lock":    "go.sum",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeGoMod,
					GoMod: GoModSpec{
						Workdir: "/app/cli",
						Spec:    "go.mod",
						Lock:    "go.sum",
					},
				},
			},
		),

		Entry("multiple go-mod entries",
			map[string]interface{}{
				"image": "image1",
				"from":  "golang:1.23-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "go-mod",
						"workdir": "/app/api",
					},
					{
						"type":    "go-mod",
						"workdir": "/app/cli",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type:  PackagesDirectiveTypeGoMod,
					GoMod: GoModSpec{Workdir: "/app/api", Spec: "go.mod", Lock: "go.sum"},
				},
				{
					Type:  PackagesDirectiveTypeGoMod,
					GoMod: GoModSpec{Workdir: "/app/cli", Spec: "go.mod", Lock: "go.sum"},
				},
			},
		),
	)

	DescribeTable("convert to directive fails when required fields are missing",
		func(yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("go-mod without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "golang:1.23-alpine",
				"packages": []map[string]interface{}{
					{
						"type": "go-mod",
					},
				},
			},
		),
	)
})
