package config

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawStapelImage packages os-pm cardinality", func() {
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		giterminismManager = NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"))
	})

	DescribeTable("preserves valid package configurations",
		func(yamlMap map[string]interface{}) {
			rawYAML, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			rawImage := &rawStapelImage{doc: &doc{Content: rawYAML}}
			Expect(yaml.UnmarshalStrict(rawYAML, rawImage)).To(Succeed())

			_, err = rawImage.toStapelImageDirective(context.Background(), giterminismManager, &Meta{}, "image1")
			Expect(err).To(Succeed())
		},
		Entry("contains no os-pm directives", map[string]interface{}{
			"image": "image1",
			"from":  "alpine",
		}),
		Entry("contains one os-pm directive", map[string]interface{}{
			"image": "image1",
			"from":  "alpine",
			"packages": []map[string]interface{}{{
				"type": "os-pm",
				"spec": []string{"curl", "jq"},
			}},
		}),
		Entry("contains repeated non-os-pm directives and one os-pm directive", map[string]interface{}{
			"image": "image1",
			"from":  "alpine",
			"packages": []map[string]interface{}{
				{"type": "go-mod", "workdir": "/app/api"},
				{"type": "os-pm", "spec": []string{"curl"}},
				{"type": "go-mod", "workdir": "/app/cli"},
			},
		}),
	)

	DescribeTable("rejects multiple os-pm directives before conversion",
		func(yamlMap map[string]interface{}) {
			rawYAML, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			rawImage := &rawStapelImage{doc: &doc{Content: rawYAML}}
			Expect(yaml.UnmarshalStrict(rawYAML, rawImage)).To(Succeed())

			_, err = rawImage.toStapelImageDirective(context.Background(), giterminismManager, &Meta{}, "image1")
			var configErr *configError
			Expect(errors.As(err, &configErr)).To(BeTrue())
			Expect(err).To(MatchError(And(
				ContainSubstring("packages"),
				ContainSubstring("os-pm"),
				ContainSubstring("only one"),
				ContainSubstring("type: os-pm"),
			)))
		},
		Entry("os-pm directives in normal order", map[string]interface{}{
			"image": "image1",
			"from":  "alpine",
			"packages": []map[string]interface{}{
				{"type": "os-pm", "spec": []string{"curl"}},
				{"type": "os-pm", "spec": []string{"jq"}},
			},
		}),
		Entry("os-pm directives in reverse order with different values", map[string]interface{}{
			"image": "image1",
			"from":  "alpine",
			"packages": []map[string]interface{}{
				{"type": "os-pm", "spec": []string{"jq"}, "env": map[string]string{"A": "b"}},
				{"type": "os-pm", "spec": []string{"curl"}, "lock": "unused"},
			},
		}),
	)
})
