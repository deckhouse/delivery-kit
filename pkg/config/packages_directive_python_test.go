package config

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

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

	directivesFromYamlPython := func(yamlMap map[string]interface{}) ([]*PackagesDirective, error) {
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
			packages, err := directivesFromYamlPython(yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].Python).To(Equal(exp.Python))
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
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonUV,
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "uv.lock",
					},
				},
			},
		),

		Entry("uv (short alias) canonicalizes to python-uv with defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "uv", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonUV,
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonUV,
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
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonPip,
						Workdir: "/app",
						Spec:    "requirements.txt",
						Lock:    "",
					},
				},
			},
		),

		Entry("pip (short alias) canonicalizes to python-pip",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "pip", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPip,
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonPip,
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
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonPoetry,
						Workdir: "/app",
						Spec:    "pyproject.toml",
						Lock:    "poetry.lock",
					},
				},
			},
		),

		Entry("poetry (short alias) canonicalizes to python-poetry",
			map[string]interface{}{
				"image": "image1",
				"from":  "python:3.12",
				"packages": []map[string]interface{}{
					{"type": "poetry", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypePythonPoetry,
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonPoetry,
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
					Python: PythonSpec{
						Manager: PackagesDirectiveTypePythonUV,
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
			_, err := directivesFromYamlPython(yamlMap)
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
	)

	It("python-poetry with Manager mismatch fails validation", func() {
		d := &PackagesDirective{
			Type: PackagesDirectiveTypePythonPoetry,
			Python: PythonSpec{
				Manager: PackagesDirectiveTypePythonUV,
				Workdir: "/app",
				Spec:    "pyproject.toml",
				Lock:    "poetry.lock",
			},
		}
		var errConf *configError
		err := d.validate()
		Expect(err).To(HaveOccurred())
		Expect(errors.As(err, &errConf)).To(BeFalse())
		Expect(err.Error()).To(ContainSubstring("does not match directive type"))
	})
})
