package api

import (
	"context"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("mutateImage", func() {
	var baseImage v1.Image

	BeforeEach(func() {
		img, err := random.Image(256, 2)
		Expect(err).NotTo(HaveOccurred())

		cf, err := img.ConfigFile()
		Expect(err).NotTo(HaveOccurred())
		cf.Config.Labels = map[string]string{"existing": "label"}

		baseImage, err = mutate.ConfigFile(img, cf)
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("preserves config mutations across layer and annotation mutations",
		func(ctx SpecContext, opts []MutateOption, expectedLabels map[string]string, expectedAnnotationKeys []string) {
			result, _, err := mutateImage(ctx, baseImage, nil, false, opts...)
			Expect(err).NotTo(HaveOccurred())

			cf, err := result.ConfigFile()
			Expect(err).NotTo(HaveOccurred())

			for k, v := range expectedLabels {
				Expect(cf.Config.Labels).To(HaveKeyWithValue(k, v))
			}

			if len(expectedAnnotationKeys) > 0 {
				manifest, err := result.Manifest()
				Expect(err).NotTo(HaveOccurred())
				for _, k := range expectedAnnotationKeys {
					Expect(manifest.Annotations).To(HaveKey(k))
				}
			}
		},

		Entry("config mutation only",
			[]MutateOption{
				WithConfigFileMutation(func(_ context.Context, cf *v1.ConfigFile) (*v1.ConfigFile, error) {
					cf.Config.Labels["added"] = "value"
					return cf, nil
				}),
			},
			map[string]string{"existing": "label", "added": "value"},
			nil,
		),

		Entry("config mutation + layer mutation preserves labels",
			[]MutateOption{
				WithConfigFileMutation(func(_ context.Context, cf *v1.ConfigFile) (*v1.ConfigFile, error) {
					cf.Config.Labels["service-label"] = "parent-stage-id"
					return cf, nil
				}),
				WithLayersMutation(func(_ context.Context, layers []v1.Layer) ([]mutate.Addendum, error) {
					var result []mutate.Addendum
					for _, l := range layers {
						result = append(result, mutate.Addendum{Layer: l})
					}
					return result, nil
				}),
			},
			map[string]string{"existing": "label", "service-label": "parent-stage-id"},
			nil,
		),

		Entry("config mutation + layer mutation + annotation mutation preserves all",
			[]MutateOption{
				WithConfigFileMutation(func(_ context.Context, cf *v1.ConfigFile) (*v1.ConfigFile, error) {
					cf.Config.Labels["werf.io/parent-stage-id"] = "abc123"
					return cf, nil
				}),
				WithLayersMutation(func(_ context.Context, layers []v1.Layer) ([]mutate.Addendum, error) {
					var result []mutate.Addendum
					for _, l := range layers {
						result = append(result, mutate.Addendum{Layer: l})
					}
					return result, nil
				}),
				WithManifestAnnotationsFunc(func(_ context.Context, m *v1.Manifest) (map[string]string, error) {
					return map[string]string{"io.cosign.signature": "sig-data"}, nil
				}),
			},
			map[string]string{"existing": "label", "werf.io/parent-stage-id": "abc123"},
			[]string{"io.cosign.signature"},
		),

		Entry("layer mutation without config mutation preserves original labels",
			[]MutateOption{
				WithLayersMutation(func(_ context.Context, layers []v1.Layer) ([]mutate.Addendum, error) {
					var result []mutate.Addendum
					for _, l := range layers {
						result = append(result, mutate.Addendum{Layer: l})
					}
					return result, nil
				}),
			},
			map[string]string{"existing": "label"},
			nil,
		),
	)

	It("uses empty config when base image has no config mutations and no layer mutations", func(ctx SpecContext) {
		img := empty.Image
		result, _, err := mutateImage(ctx, img, nil, false,
			WithManifestAnnotationsFunc(func(_ context.Context, _ *v1.Manifest) (map[string]string, error) {
				return map[string]string{"ann": "val"}, nil
			}),
		)
		Expect(err).NotTo(HaveOccurred())

		manifest, err := result.Manifest()
		Expect(err).NotTo(HaveOccurred())
		Expect(manifest.Annotations).To(HaveKeyWithValue("ann", "val"))
	})
})
