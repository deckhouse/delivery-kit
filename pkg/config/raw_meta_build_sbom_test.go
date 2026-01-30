package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawMetaBuildSbom", func() {
	BeforeEach(func() {
		// NOTE: global var used by UnmarshalYAML parent tracking across many config raw structs.
		parentStack = util.NewStack()
	})

	DescribeTable("unmarshal and convert to directive",
		func(yamlMap map[string]interface{}, expected *MetaBuildSbom) {
			if len(yamlMap) == 0 {
				Fail("yamlMap should not be empty")
			}

			rawYaml, err := yaml.Marshal(yamlMap)
			Expect(err).To(Succeed())

			doc := &doc{Content: rawYaml}

			var rawSbom rawMetaBuildSbom
			rawSbom.rawMetaBuild = &rawMetaBuild{
				rawMeta: &rawMeta{doc: doc},
			}

			Expect(yaml.UnmarshalStrict(doc.Content, &rawSbom)).To(Succeed())
			Expect(rawSbom.toDirective()).To(Equal(expected))
		},
		Entry(
			"should handle enable=true",
			map[string]interface{}{
				"enable": true,
			},
			&MetaBuildSbom{
				Enable: true,
			},
		),
		Entry(
			"should handle enable=false",
			map[string]interface{}{
				"enable": false,
			},
			&MetaBuildSbom{
				Enable: false,
			},
		),
	)
})
