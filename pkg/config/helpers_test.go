package config

import (
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"
)

func directivesFromYaml(giterminismManager *GiterminismManagerStub, yamlMap map[string]interface{}) ([]*PackagesDirective, error) {
	rawYaml, err := yaml.Marshal(yamlMap)
	Expect(err).To(Succeed())

	doc := &doc{Content: rawYaml}
	rawStapelImage := &rawStapelImage{doc: doc}

	if err := yaml.UnmarshalStrict(doc.Content, rawStapelImage); err != nil {
		return nil, err
	}

	stapelImage, err := rawStapelImage.toStapelImageDirective(giterminismManager, &Meta{}, "image1")
	if err != nil {
		return nil, err
	}
	return stapelImage.Packages, nil
}
