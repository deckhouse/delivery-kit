package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective python", func() {
	var localGitRepo *LocalGitRepoStub
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		localGitRepo = NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
		giterminismManager = NewGiterminismManagerStub(localGitRepo)
	})

	DescribeTable("unmarshal and convert succeed",
		func(yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(giterminismManager, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].FileBased).To(Equal(exp.FileBased))
			}
		},

		Entry("python-uv with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-uv", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonUV,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "uv.lock",
					},
				},
			},
		),

		Entry("python-pip with only workdir defaults spec and empty lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-pip", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPip,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "requirements.txt",
						Lock:    "",
					},
				},
			},
		),

		Entry("python-poetry with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-poetry", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPoetry,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "poetry.lock",
					},
				},
			},
		),

		Entry("python-uv with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-uv",
						"workdir": "/app",
						"spec":    "custom.toml",
						"lock":    "custom.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonUV,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "custom.toml",
						Lock:    "custom.lock",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails when required fields are missing",
		func(yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(giterminismManager, yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("python-uv without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "python-uv"},
				},
			},
		),

		Entry("python-pip with spec as list instead of string",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-pip",
						"workdir": "/app",
						"spec":    []string{"requests"},
					},
				},
			},
		),

		Entry("unknown type is rejected",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "pythonn-uv", "workdir": "/app"},
				},
			},
		),

		Entry("python-pip with lock field is rejected (pip has no lock semantics)",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{
						"type":    "python-pip",
						"workdir": "/app",
						"lock":    "requirements.lock",
					},
				},
			},
		),
	)
})
