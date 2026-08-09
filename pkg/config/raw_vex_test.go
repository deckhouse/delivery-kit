package config

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawVex (YAML-level validation)", func() {
	DescribeTable(
		"scalar string and struct form YAML unmarshaling",
		func(yamlContent, expectedDocument string, unmarshalMatcher, configErrMatcher OmegaMatcher) {
			// NOTE: global var used by UnmarshalYAML parent tracking across many config raw structs.
			parentStack = util.NewStack()

			rawV := &rawVex{
				doc: &doc{
					RenderFilePath: "werf.yaml",
					Content:        []byte(yamlContent),
				},
			}

			err := yaml.UnmarshalStrict([]byte(yamlContent), rawV)

			Expect(err).To(unmarshalMatcher)

			if err != nil {
				var confErr *configError
				Expect(errors.As(err, &confErr)).To(configErrMatcher)
				return
			}

			Expect(rawV).ToNot(BeNil())
			Expect(rawV.Document).To(Equal(expectedDocument))
		},

		Entry(
			"should parse scalar string form: vex: path/to/file",
			"path/to/file",
			"path/to/file",
			Succeed(),
			BeFalse(),
		),

		Entry(
			"should parse struct form: vex:\n  document: path/to/file",
			"document: path/to/file",
			"path/to/file",
			Succeed(),
			BeFalse(),
		),

		Entry(
			"should fail when unknown fields are present in struct form",
			"document: path/to/file\nunknown: value",
			"",
			HaveOccurred(),
			BeTrue(),
		),
	)
})
