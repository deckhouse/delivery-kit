package artifact

import (
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
)

const testArtifactType = "application/vnd.dsse.envelope.v1+json"

var _ = Describe("buildArtifactImage", func() {
	annotations := map[string]string{
		image.WerfImageNameAnnotation: "my-app",
		image.WerfChecksumAnnotation:  "checksum-v1",
		image.WerfPlatformAnnotation:  "linux/amd64",
	}

	It("should write werf annotations into the artifact manifest", func() {
		img, err := buildArtifactImage([]byte(`{"payload":1}`), testArtifactType, annotations)
		Expect(err).To(Succeed())

		manifest, err := img.Manifest()
		Expect(err).To(Succeed())
		Expect(manifest.Annotations).To(Equal(annotations))
	})

	It("should declare the artifact type through the config media type", func() {
		img, err := buildArtifactImage([]byte(`{"payload":1}`), testArtifactType, annotations)
		Expect(err).To(Succeed())

		manifest, err := img.Manifest()
		Expect(err).To(Succeed())
		Expect(manifest.Config.MediaType).To(Equal(types.MediaType(testArtifactType)))
	})

	It("should resolve the artifact type from the manifest without an explicit field", func() {
		img, err := buildArtifactImage([]byte(`{"payload":1}`), testArtifactType, annotations)
		Expect(err).To(Succeed())

		artifactType, err := partial.ArtifactType(img)
		Expect(err).To(Succeed())
		Expect(artifactType).To(Equal(testArtifactType))
	})

	It("should propagate artifact type and annotations into the computed descriptor", func() {
		img, err := buildArtifactImage([]byte(`{"payload":1}`), testArtifactType, annotations)
		Expect(err).To(Succeed())

		desc, err := partial.Descriptor(img)
		Expect(err).To(Succeed())
		Expect(desc.ArtifactType).To(Equal(testArtifactType))
		Expect(desc.MediaType).To(Equal(types.OCIManifestSchema1))
	})

	It("should store the payload as the single layer", func() {
		payload := []byte(`{"payload":1}`)

		img, err := buildArtifactImage(payload, testArtifactType, annotations)
		Expect(err).To(Succeed())

		layers, err := img.Layers()
		Expect(err).To(Succeed())
		Expect(layers).To(HaveLen(1))

		content, err := readLayerContent(layers[0])
		Expect(err).To(Succeed())
		Expect(content).To(Equal(payload))
	})

	It("should omit annotations when none are provided", func() {
		img, err := buildArtifactImage([]byte(`{"payload":1}`), testArtifactType, nil)
		Expect(err).To(Succeed())

		manifest, err := img.Manifest()
		Expect(err).To(Succeed())
		Expect(manifest.Annotations).To(BeEmpty())
	})

	It("should produce distinct digests for artifacts differing only by image name", func() {
		payload := []byte(`{"payload":1}`)

		imgA, err := buildArtifactImage(payload, testArtifactType, map[string]string{image.WerfImageNameAnnotation: "app-a"})
		Expect(err).To(Succeed())
		imgB, err := buildArtifactImage(payload, testArtifactType, map[string]string{image.WerfImageNameAnnotation: "app-b"})
		Expect(err).To(Succeed())

		digestA, err := imgA.Digest()
		Expect(err).To(Succeed())
		digestB, err := imgB.Digest()
		Expect(err).To(Succeed())

		Expect(digestA).ToNot(Equal(digestB))
	})
})

var _ = Describe("OCIStore.artifactAnnotations", func() {
	It("should collect every provided annotation", func() {
		store := NewOCIStore("example.org/repo", "my-app")

		Expect(store.artifactAnnotations("checksum-v1", "linux/amd64")).To(Equal(map[string]string{
			image.WerfImageNameAnnotation: "my-app",
			image.WerfChecksumAnnotation:  "checksum-v1",
			image.WerfPlatformAnnotation:  "linux/amd64",
		}))
	})

	It("should skip empty values", func() {
		store := NewOCIStore("example.org/repo", "")

		Expect(store.artifactAnnotations("", "")).To(BeEmpty())
	})
})
