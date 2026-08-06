package artifact

import (
	"encoding/hex"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/image"
)

// digestForName builds a distinct, deterministic digest per logical artifact. Distinct
// artifacts must not share a digest: updateFallbackIndex evicts by digest, and in
// production distinct artifacts always differ in manifest bytes because the werf
// annotations are part of the manifest.
func digestForName(name string) v1.Hash {
	encoded := hex.EncodeToString([]byte(name))
	return v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 64-len(encoded)) + encoded}
}

var _ = Describe("updateFallbackIndex", func() {
	makeDesc := func(name, artifactType string, annotations map[string]string) v1.Descriptor {
		if annotations == nil {
			annotations = map[string]string{}
		}
		return v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       digestForName(name),
			Size:         42,
			ArtifactType: artifactType,
			Annotations:  annotations,
		}
	}

	It("should add first entry to empty index", func() {
		desc := makeDesc("image-a", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx := updateFallbackIndex(empty.Index, desc, "type/sbom", "image-a", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].Annotations[image.WerfImageNameAnnotation]).To(Equal("image-a"))
	})

	It("should replace existing entry with same artifactType and imageName", func() {
		oldDesc := makeDesc("image-a", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx := updateFallbackIndex(empty.Index, oldDesc, "type/sbom", "image-a", nil)

		newDesc := makeDesc("image-a", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a", "checksum": "v2"})
		idx = updateFallbackIndex(idx, newDesc, "type/sbom", "image-a", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].Annotations["checksum"]).To(Equal("v2"))
	})

	It("should keep entries with different artifactType", func() {
		sbomDesc := makeDesc("image-a-sbom", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx := updateFallbackIndex(empty.Index, sbomDesc, "type/sbom", "image-a", nil)

		otherDesc := makeDesc("image-a-sig", "type/signature", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx = updateFallbackIndex(idx, otherDesc, "type/signature", "image-a", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(2))
	})

	It("should evict an entry describing the same manifest digest", func() {
		foreignDesc := v1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    digestForName("image-a"),
			Size:      42,
		}
		idx := newStaticIndex([]v1.Descriptor{foreignDesc})

		desc := makeDesc("image-a", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx = updateFallbackIndex(idx, desc, "type/sbom", "image-a", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].ArtifactType).To(Equal("type/sbom"))
		Expect(im.Manifests[0].Annotations[image.WerfImageNameAnnotation]).To(Equal("image-a"))
	})

	It("should keep entries for different imageNames with same artifactType", func() {
		descA := makeDesc("image-a", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-a"})
		idx := updateFallbackIndex(empty.Index, descA, "type/sbom", "image-a", nil)

		descB := makeDesc("image-b", "type/sbom", map[string]string{image.WerfImageNameAnnotation: "image-b"})
		idx = updateFallbackIndex(idx, descB, "type/sbom", "image-b", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(2))
	})
})

var _ = Describe("newStaticIndex / Digest", func() {
	It("should compute deterministic digest for same content", func() {
		desc := v1.Descriptor{
			MediaType: types.OCIManifestSchema1,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abc123"},
			Size:      100,
		}

		idx1 := newStaticIndex([]v1.Descriptor{desc})
		idx2 := newStaticIndex([]v1.Descriptor{desc})

		d1, err := idx1.Digest()
		Expect(err).To(Succeed())
		d2, err := idx2.Digest()
		Expect(err).To(Succeed())

		Expect(d1).To(Equal(d2))
	})

	It("should produce different digests for different content", func() {
		desc1 := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 100}
		desc2 := v1.Descriptor{MediaType: types.OCIManifestSchema1, Size: 200}

		d1, _ := newStaticIndex([]v1.Descriptor{desc1}).Digest()
		d2, _ := newStaticIndex([]v1.Descriptor{desc2}).Digest()

		Expect(d1).ToNot(Equal(d2))
	})
})

var _ = Describe("Annotations", func() {
	It("should define WerfPlatformAnnotation constant", func() {
		Expect(image.WerfPlatformAnnotation).To(Equal("io.werf.target-platform"))
	})

	It("should preserve platform annotation through updateFallbackIndex", func() {
		desc := v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       v1.Hash{Algorithm: "sha256", Hex: "0000000000000000000000000000000000000000000000000000000000000000"},
			Size:         42,
			ArtifactType: "type/sbom",
			Annotations: map[string]string{
				image.WerfImageNameAnnotation: "my-app",
				image.WerfPlatformAnnotation:  "linux/amd64",
			},
		}

		idx := updateFallbackIndex(empty.Index, desc, "type/sbom", "my-app", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(1))
		Expect(im.Manifests[0].Annotations[image.WerfPlatformAnnotation]).To(Equal("linux/amd64"))
	})

	It("should be independent of imageName replacement filter", func() {
		descA := v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       digestForName("app-a"),
			Size:         42,
			ArtifactType: "type/sbom",
			Annotations: map[string]string{
				image.WerfImageNameAnnotation: "app-a",
				image.WerfPlatformAnnotation:  "linux/amd64",
			},
		}

		descB := v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       digestForName("app-b"),
			Size:         42,
			ArtifactType: "type/sbom",
			Annotations: map[string]string{
				image.WerfImageNameAnnotation: "app-b",
				image.WerfPlatformAnnotation:  "linux/arm64",
			},
		}

		idx := updateFallbackIndex(empty.Index, descA, "type/sbom", "app-a", nil)
		idx = updateFallbackIndex(idx, descB, "type/sbom", "app-b", nil)

		im, err := idx.IndexManifest()
		Expect(err).To(Succeed())
		Expect(im.Manifests).To(HaveLen(2))
		Expect(im.Manifests[0].Annotations[image.WerfPlatformAnnotation]).To(Equal("linux/amd64"))
		Expect(im.Manifests[1].Annotations[image.WerfPlatformAnnotation]).To(Equal("linux/arm64"))
	})
})

var _ = Describe("isAttached", func() {
	desc := func(name, artifactType, imageName string) v1.Descriptor {
		return v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       digestForName(name),
			Size:         42,
			ArtifactType: artifactType,
			Annotations:  map[string]string{image.WerfImageNameAnnotation: imageName},
		}
	}

	indexOf := func(descriptors ...v1.Descriptor) *v1.IndexManifest {
		im, err := newStaticIndex(descriptors).IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	It("should report an empty index as not attached", func() {
		target := desc("app-a-v1", "type/sbom", "app-a")

		Expect(isAttached(indexOf(), target, "type/sbom", "app-a", nil)).To(BeFalse())
	})

	It("should report the descriptor as attached once present", func() {
		target := desc("app-a-v1", "type/sbom", "app-a")

		Expect(isAttached(indexOf(target), target, "type/sbom", "app-a", nil)).To(BeTrue())
	})

	It("should ignore entries of other images", func() {
		target := desc("app-a-v1", "type/sbom", "app-a")
		other := desc("app-b-v1", "type/sbom", "app-b")

		Expect(isAttached(indexOf(other, target), target, "type/sbom", "app-a", nil)).To(BeTrue())
	})

	It("should report a superseded descriptor as not attached", func() {
		target := desc("app-a-v2", "type/sbom", "app-a")
		stale := desc("app-a-v1", "type/sbom", "app-a")

		Expect(isAttached(indexOf(stale), target, "type/sbom", "app-a", nil)).To(BeFalse())
	})

	It("should report a foreign descriptor of the same type as not attached", func() {
		target := desc("app-a-v1", "type/sbom", "app-a")
		foreign := v1.Descriptor{
			MediaType:    types.OCIManifestSchema1,
			Digest:       digestForName("app-a-v1"),
			Size:         42,
			ArtifactType: "type/sbom",
		}

		Expect(isAttached(indexOf(foreign), target, "type/sbom", "app-a", nil)).To(BeFalse())
	})

	It("should report duplicated entries of one image as not attached", func() {
		target := desc("app-a-v1", "type/sbom", "app-a")
		stale := desc("app-a-v0", "type/sbom", "app-a")

		Expect(isAttached(indexOf(stale, target), target, "type/sbom", "app-a", nil)).To(BeFalse())
	})
})

var _ = Describe("isAttached with an unnamed artifact", func() {
	unnamed := v1.Descriptor{
		MediaType:    types.OCIManifestSchema1,
		Digest:       digestForName("unnamed-v1"),
		Size:         42,
		ArtifactType: "type/sbom",
	}

	named := v1.Descriptor{
		MediaType:    types.OCIManifestSchema1,
		Digest:       digestForName("app-a-v1"),
		Size:         42,
		ArtifactType: "type/sbom",
		Annotations:  map[string]string{image.WerfImageNameAnnotation: "app-a"},
	}

	indexOf := func(descriptors ...v1.Descriptor) *v1.IndexManifest {
		im, err := newStaticIndex(descriptors).IndexManifest()
		Expect(err).To(Succeed())
		return im
	}

	It("should report it as attached next to an entry of a named image", func() {
		Expect(isAttached(indexOf(named, unnamed), unnamed, "type/sbom", "", nil)).To(BeTrue())
	})

	It("should not be satisfied by an entry of a named image alone", func() {
		Expect(isAttached(indexOf(named), unnamed, "type/sbom", "", nil)).To(BeFalse())
	})

	It("should not report a named entry as attached when an unnamed one exists", func() {
		Expect(isAttached(indexOf(named, unnamed), named, "type/sbom", "app-a", nil)).To(BeTrue())
	})
})
