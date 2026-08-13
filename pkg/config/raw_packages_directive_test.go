package config

import (
	"context"
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

	directivesFromYaml := func(ctx context.Context, yamlMap map[string]interface{}) ([]*PackagesDirective, error) {
		rawYaml, err := yaml.Marshal(yamlMap)
		Expect(err).To(Succeed())

		doc := &doc{Content: rawYaml}
		rawStapelImage := &rawStapelImage{doc: doc}

		Expect(yaml.UnmarshalStrict(doc.Content, rawStapelImage)).To(Succeed())

		stapelImage, err := rawStapelImage.toStapelImageDirective(ctx, giterminismManager, &Meta{}, "image1")
		if err != nil {
			return nil, err
		}
		return stapelImage.Packages, nil
	}

	DescribeTable("unmarshal and convert to directive succeed",
		func(ctx SpecContext, yamlMap map[string]interface{}, expectedPackages []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expectedPackages)))
			for i, expected := range expectedPackages {
				Expect(packages[i].Type).To(Equal(expected.Type))
				Expect(packages[i].FileBased).To(Equal(expected.FileBased))
			}
		},

		Entry("os-pm with file-based spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "pm.yaml",
						"lock": "pm.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
				},
			},
		),

		Entry("os-pm with minimal config (defaults to pm.yaml/pm.lock)",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "pm.yaml",
						"lock": "pm.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
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
						"spec": "pm.yaml",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails for invalid content",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, yamlMap)
			Expect(err).To(HaveOccurred())
		},

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

		Entry("invalid env var name 1INVALID",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "pm.yaml",
						"env": map[string]interface{}{
							"1INVALID": "value",
						},
					},
				},
			},
		),

		Entry("invalid env var name has=equals",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "pm.yaml",
						"env": map[string]interface{}{
							"has=equals": "value",
						},
					},
				},
			},
		),

		Entry("invalid env var name with special chars",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"spec": "pm.yaml",
						"env": map[string]interface{}{
							"MY-VAR": "value",
						},
					},
				},
			},
		),

		Entry("os-pm with workdir is rejected",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type":    "os-pm",
						"workdir": "/app",
						"spec":    "pm.yaml",
					},
				},
			},
		),

		Entry("os-pm with list spec is rejected",
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
		),
	)

	DescribeTable("convert to directive succeeds with valid env var names",
		func(ctx SpecContext, yamlMap map[string]interface{}, expectedPackages []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, yamlMap)
			Expect(err).To(Succeed())
			Expect(packages).To(HaveLen(len(expectedPackages)))
			for i, expected := range expectedPackages {
				Expect(packages[i].Type).To(Equal(expected.Type))
				Expect(packages[i].FileBased).To(Equal(expected.FileBased))
				Expect(packages[i].Env).To(Equal(expected.Env))
			}
		},

		Entry("valid env var _MY_VAR",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"env": map[string]interface{}{
							"_MY_VAR": "value",
						},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
					Env: map[string]string{
						"_MY_VAR": "value",
					},
				},
			},
		),

		Entry("valid env var HTTP_PROXY",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"env": map[string]interface{}{
							"HTTP_PROXY": "http://proxy:8080",
						},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
					Env: map[string]string{
						"HTTP_PROXY": "http://proxy:8080",
					},
				},
			},
		),

		Entry("valid env var DOCKER_CONFIG",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"env": map[string]interface{}{
							"DOCKER_CONFIG": "/run/secrets/docker",
						},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
					Env: map[string]string{
						"DOCKER_CONFIG": "/run/secrets/docker",
					},
				},
			},
		),

		Entry("valid env var DEBIAN_FRONTEND",
			map[string]interface{}{
				"image": "image1",
				"from":  "alpine:latest",
				"packages": []map[string]interface{}{
					{
						"type": "os-pm",
						"env": map[string]interface{}{
							"DEBIAN_FRONTEND": "noninteractive",
						},
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
					Env: map[string]string{
						"DEBIAN_FRONTEND": "noninteractive",
					},
				},
			},
		),
	)
})
