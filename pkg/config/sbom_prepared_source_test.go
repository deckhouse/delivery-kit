package config

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v2"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("prepareWerfConfig prepared source images", func() {
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		giterminismManager = NewGiterminismManagerStub(NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0"))
	})

	prepare := func(images []map[string]interface{}, sbom bool) error {
		GinkgoHelper()
		var rawImages []*rawStapelImage
		for _, image := range images {
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

	// The toolchain the prepared source collects its files out of.
	bootstrap := map[string]interface{}{
		"image": "builder", "from": "ubuntu:22.04", "final": false,
		"imageSpec": map[string]interface{}{"config": map[string]interface{}{
			"labels": map[string]interface{}{SBOMBuildContextLabel: `{"version":1,"bootstrap":true}`},
		}},
	}

	preparedSource := func(overrides map[string]interface{}) map[string]interface{} {
		image := map[string]interface{}{
			"image": "go-source", "from": "scratch", "final": false,
			"import": []map[string]interface{}{
				{"image": "builder", "add": "/usr/local/go/src", "to": "/src", "before": "install"},
			},
			"imageSpec": map[string]interface{}{"config": map[string]interface{}{
				"labels": map[string]interface{}{SBOMBuildContextLabel: `{"version":1,"preparedSource":true}`},
			}},
		}
		for key, value := range overrides {
			image[key] = value
		}

		return image
	}

	recipe := func(overrides map[string]interface{}) []map[string]interface{} {
		return []map[string]interface{}{bootstrap, preparedSource(overrides)}
	}

	It("accepts a prepared source that only imports from images of this project", func() {
		Expect(prepare(recipe(nil), true)).To(Succeed())
	})

	// Everything it may ship was put there by an import. A base image underneath it
	// would bring in bytes it never collected.
	It("refuses a prepared source built on a base image", func() {
		Expect(prepare(recipe(map[string]interface{}{"from": "ubuntu:22.04"}), true)).
			To(MatchError(ContainSubstring(`image "go-source" is declared a prepared source, so it is built from scratch`)))
	})

	DescribeTable("refuses a prepared source that makes anything of its own",
		func(overrides map[string]interface{}, expected string) {
			Expect(prepare(recipe(overrides), true)).To(MatchError(ContainSubstring(expected)))
		},
		Entry("a command before install",
			map[string]interface{}{"shell": map[string]interface{}{"beforeInstall": []string{"echo hi"}}},
			`image "go-source" is declared a prepared source, so it runs no commands`),
		Entry("a command at install",
			map[string]interface{}{"shell": map[string]interface{}{"install": []string{"make"}}},
			`so it runs no commands`),
		Entry("a command before setup",
			map[string]interface{}{"shell": map[string]interface{}{"beforeSetup": []string{"make"}}},
			`so it runs no commands`),
		Entry("a command at setup",
			map[string]interface{}{"shell": map[string]interface{}{"setup": []string{"make"}}},
			`so it runs no commands`),
		Entry("a git mapping",
			map[string]interface{}{"git": []map[string]interface{}{{"add": "/", "to": "/app"}}},
			`image "go-source" is declared a prepared source, so it adds nothing from a repository`),
		Entry("a mount",
			map[string]interface{}{"mount": []map[string]interface{}{{"from": "tmp_dir", "to": "/var/cache"}}},
			`image "go-source" is declared a prepared source, so it mounts nothing`),
		Entry("a secret",
			map[string]interface{}{"secrets": []map[string]interface{}{{"id": "token", "value": "x"}}},
			`image "go-source" is declared a prepared source, so it takes no secrets`),
		Entry("a dependency on another image",
			map[string]interface{}{"dependencies": []map[string]interface{}{{"from": "builder", "before": "install", "imports": []map[string]interface{}{{"type": "ImageName", "targetEnv": "BUILDER"}}}}},
			`image "go-source" is declared a prepared source, so it declares no dependencies`),
		Entry("being delivered as a final image",
			map[string]interface{}{"final": nil},
			`image "go-source" is declared a prepared source, so it states final: false`),
		Entry("a packages directive",
			map[string]interface{}{"packages": []map[string]interface{}{{"type": "os-pm", "spec": []string{"bash"}}}},
			`image "go-source" is declared a prepared source, so it installs no packages`),
	)

	// An image of this project is either a declared bootstrap image or one this very
	// build verifies; an image from outside is neither.
	It("refuses a prepared source importing from outside this project", func() {
		Expect(prepare(recipe(map[string]interface{}{
			"import": []map[string]interface{}{
				{"image": "builder", "add": "/usr/local/go/src", "to": "/src", "before": "install"},
				{"image": "registry.example.org/vendor/toolchain:v1", "add": "/src", "to": "/vendor", "before": "install"},
			},
		}), true)).To(MatchError(ContainSubstring(`image "go-source" is declared a prepared source and imports from "registry.example.org/vendor/toolchain:v1", which is not an image of this project`)))
	})

	It("refuses an image declared both a prepared source and a bootstrap image", func() {
		Expect(prepare(recipe(map[string]interface{}{
			"imageSpec": map[string]interface{}{"config": map[string]interface{}{
				"labels": map[string]interface{}{SBOMBuildContextLabel: `{"version":1,"preparedSource":true,"bootstrap":true}`},
			}},
		}), true)).To(MatchError(ContainSubstring(`image "go-source" is declared both a prepared source and a bootstrap image`)))
	})

	// The declaration is read by the convergence this project runs, and a recipe that
	// does not run it is not held to what it would have meant.
	It("says nothing about a prepared source when the SBOM is not enabled", func() {
		Expect(prepare(recipe(map[string]interface{}{
			"from":  "ubuntu:22.04",
			"shell": map[string]interface{}{"install": []string{"make"}},
		}), false)).To(Succeed())
	})

	// What makes an image a prepared source is the declaration, not what it looks like.
	It("says nothing about an image that declares nothing", func() {
		Expect(prepare([]map[string]interface{}{bootstrap, {
			"image": "go-source", "from": "ubuntu:22.04",
			"shell": map[string]interface{}{"install": []string{"make"}},
			"import": []map[string]interface{}{
				{"image": "builder", "add": "/usr/local/go/src", "to": "/src", "before": "install"},
			},
			"imageSpec": map[string]interface{}{"config": map[string]interface{}{
				"labels": map[string]interface{}{"pkg.name": "go-source", "pkg.version": "1.27.3"},
			}},
		}}, true)).To(Succeed())
	})
})
