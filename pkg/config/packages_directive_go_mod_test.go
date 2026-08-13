package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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

	DescribeTable("unmarshal and convert succeed",
		func(ctx SpecContext, yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].FileBased).To(Equal(exp.FileBased))
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
					FileBased: FileBasedSpec{
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
					FileBased: FileBasedSpec{
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
					Type:      PackagesDirectiveTypeGoMod,
					FileBased: FileBasedSpec{Workdir: "/app/api", Spec: "go.mod", Lock: "go.sum"},
				},
				{
					Type:      PackagesDirectiveTypeGoMod,
					FileBased: FileBasedSpec{Workdir: "/app/cli", Spec: "go.mod", Lock: "go.sum"},
				},
			},
		),
	)

	DescribeTable("convert to directive fails when required fields are missing",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
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
