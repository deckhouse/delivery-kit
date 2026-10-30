package config

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("prepareWerfConfig bootstrap images", func() {
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		giterminismManager = NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"))
	})

	// A recipe of two images: one declaring itself a bootstrap image, one ordinary.
	prepare := func(bootstrap, app map[string]interface{}, sbom bool) error {
		GinkgoHelper()
		var rawImages []*rawStapelImage
		for _, image := range []map[string]interface{}{bootstrap, app} {
			if image == nil {
				continue
			}
			rawYaml, err := yaml.Marshal(image)
			Expect(err).To(Succeed())
			doc := &doc{Content: rawYaml}
			rawImage := &rawStapelImage{doc: doc}
			Expect(yaml.UnmarshalStrict(doc.Content, rawImage)).To(Succeed())
			rawImages = append(rawImages, rawImage)
		}

		meta := &Meta{}
		meta.ConfigVersion = 1
		meta.Project = "test"
		if sbom {
			meta.Build.Sbom = &MetaBuildSbom{Enable: true}
		}

		_, err := prepareWerfConfig(context.Background(), giterminismManager, rawImages, nil, meta)

		return err
	}

	builder := func(overrides map[string]interface{}) map[string]interface{} {
		image := map[string]interface{}{
			"image": "builder",
			"from":  "ubuntu:22.04",
			"final": false,
			"imageSpec": map[string]interface{}{
				"config": map[string]interface{}{
					"labels": map[string]interface{}{SBOMBuildContextLabel: `{"version":1,"bootstrap":true}`},
				},
			},
		}
		for key, value := range overrides {
			image[key] = value
		}

		return image
	}

	importing := map[string]interface{}{
		"image": "app",
		"from":  "ubuntu:22.04",
		"import": []map[string]interface{}{
			{"image": "builder", "add": "/usr/local/bin/tool", "to": "/usr/local/bin/tool", "before": "install"},
		},
	}

	It("accepts a bootstrap image that is only imported from", func() {
		Expect(prepare(builder(nil), importing, true)).To(Succeed())
	})

	// Shipping it would publish an image whose own composition nothing describes.
	It("refuses a bootstrap image that is final", func() {
		Expect(prepare(builder(map[string]interface{}{"final": true}), importing, true)).
			To(MatchError(ContainSubstring(`image "builder" is declared a bootstrap image, so it cannot be final`)))
	})

	// Standing underneath an image carries every byte of it into that image, which is
	// the whole of what being imported from is not.
	It("refuses an image built from a bootstrap image", func() {
		based := map[string]interface{}{"image": "app", "from": "builder"}
		Expect(prepare(builder(nil), based, true)).
			To(MatchError(ContainSubstring(`image "app" is built from "builder", which is declared a bootstrap image`)))
	})

	It("refuses an image that names a bootstrap image as a dependency", func() {
		dependent := map[string]interface{}{
			"image": "app", "from": "ubuntu:22.04",
			"dependencies": []map[string]interface{}{
				{"image": "builder", "before": "install", "imports": []map[string]interface{}{{"type": "ImageName", "targetEnv": "BUILDER"}}},
			},
		}
		Expect(prepare(builder(nil), dependent, true)).
			To(MatchError(ContainSubstring(`image "app" names "builder" as a dependency, which is declared a bootstrap image`)))
	})

	It("refuses a bootstrap image nothing imports from", func() {
		alone := map[string]interface{}{"image": "app", "from": "ubuntu:22.04"}
		Expect(prepare(builder(nil), alone, true)).
			To(MatchError(ContainSubstring(`image "builder" is declared a bootstrap image, but no image imports from it`)))
	})

	// The declaration is read by the convergence this project runs, and a recipe that
	// does not run it is not held to what it would have meant.
	It("says nothing about a bootstrap image when the SBOM is not enabled", func() {
		Expect(prepare(builder(map[string]interface{}{"final": true}), importing, false)).To(Succeed())
	})
})
