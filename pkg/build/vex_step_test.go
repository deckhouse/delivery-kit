package build

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/werf/werf/v2/pkg/attestation"
	"github.com/werf/werf/v2/pkg/image"
	"github.com/werf/werf/v2/pkg/vex"
	"github.com/werf/werf/v2/test/mock"
)

var _ = Describe("VexStep", func() {
	Describe("checkVEXPublishNeeded", func() {
		const (
			parentDigest      = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
			matchingChecksum  = "abc123"
			differentChecksum = "xyz789"
		)

		It("should skip VEX publish when a bundle artifact exists with matching checksum", func(ctx SpecContext) {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()

			mockStore := mock.NewMockStore(ctrl)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{
					Annotations: map[string]string{
						image.WerfChecksumAnnotation: matchingChecksum,
					},
				}, true, nil,
			)

			needed, err := checkVEXPublishNeeded(ctx, mockStore, parentDigest, matchingChecksum)
			Expect(err).ToNot(HaveOccurred())
			Expect(needed).To(BeFalse())
		})

		It("should skip VEX publish when a bare-DSSE artifact exists with matching checksum", func(ctx SpecContext) {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()

			mockStore := mock.NewMockStore(ctrl)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{}, false, nil,
			)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{
					Annotations: map[string]string{
						image.WerfChecksumAnnotation: matchingChecksum,
					},
				}, true, nil,
			)

			needed, err := checkVEXPublishNeeded(ctx, mockStore, parentDigest, matchingChecksum)
			Expect(err).ToNot(HaveOccurred())
			Expect(needed).To(BeFalse())
		})

		It("should proceed with VEX publish when checksum differs", func(ctx SpecContext) {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()

			mockStore := mock.NewMockStore(ctrl)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{}, false, nil,
			)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{
					Annotations: map[string]string{
						image.WerfChecksumAnnotation: differentChecksum,
					},
				}, true, nil,
			)

			needed, err := checkVEXPublishNeeded(ctx, mockStore, parentDigest, matchingChecksum)
			Expect(err).ToNot(HaveOccurred())
			Expect(needed).To(BeTrue())
		})

		It("should proceed with VEX publish when no artifact exists", func(ctx SpecContext) {
			ctrl := gomock.NewController(GinkgoT())
			defer ctrl.Finish()

			mockStore := mock.NewMockStore(ctrl)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, attestation.BundleMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{}, false, nil,
			)
			mockStore.EXPECT().GetAttached(ctx, parentDigest, vex.DSSEMediaType, vex.VEXPredicateTypes).Return(
				v1.Descriptor{}, false, nil,
			)

			needed, err := checkVEXPublishNeeded(ctx, mockStore, parentDigest, matchingChecksum)
			Expect(err).ToNot(HaveOccurred())
			Expect(needed).To(BeTrue())
		})
	})

	Describe("calculateVEXChecksum", func() {
		const parentDigest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

		vexJSON := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)

		It("is stable for identical inputs", func() {
			Expect(calculateVEXChecksum(vexJSON, parentDigest, "")).To(Equal(calculateVEXChecksum(vexJSON, parentDigest, "")))
		})

		DescribeTable("changes when any identity component changes",
			func(otherJSON []byte, otherDigest, otherIdentity string) {
				base := calculateVEXChecksum(vexJSON, parentDigest, "")
				Expect(calculateVEXChecksum(otherJSON, otherDigest, otherIdentity)).ToNot(Equal(base))
			},
			Entry("document content changed", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{}]}`), parentDigest, ""),
			Entry("image digest changed", vexJSON, "sha256:1111111111111111111111111111111111111111111111111111111111111111", ""),
			Entry("signing enabled (fingerprint added)", vexJSON, parentDigest, "fingerprint-a"),
		)

		It("changes when the signing key is rotated", func() {
			Expect(calculateVEXChecksum(vexJSON, parentDigest, "fingerprint-a")).ToNot(Equal(calculateVEXChecksum(vexJSON, parentDigest, "fingerprint-b")))
		})
	})
})
