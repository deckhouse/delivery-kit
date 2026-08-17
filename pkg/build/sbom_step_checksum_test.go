package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("SbomStep Checksum", func() {
	It("GOST config does not change unsigned checksum", func() {
		step := &sbomStep{}
		plain := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		withGost := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{
			Gost: gost.Config{
				AttackSurface:    gost.GostValueYes,
				SecurityFunction: gost.GostValueIndirect,
			},
		}, "", "")
		Expect(plain).To(Equal(withGost))
	})

	It("same inputs produce same checksum", func() {
		step := &sbomStep{}
		a := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		b := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		Expect(a).To(Equal(b))
	})

	It("signer identity changes checksum", func() {
		step := &sbomStep{}
		unsigned := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		signed := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:abc", "")
		Expect(unsigned).NotTo(Equal(signed))
	})

	It("different signer identities produce different checksums", func() {
		step := &sbomStep{}
		a := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:key1", "")
		b := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:key2", "")
		Expect(a).NotTo(Equal(b))
	})

	It("format version change invalidates cache", func() {
		step := &sbomStep{}
		checksum := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		Expect(checksum).NotTo(Equal("aa969eabe2faad149265a94e60b173e527e0bc27898afcd0ec4e85a06b28f29b"),
			"checksum must differ from format-v1 era (before format version was added)")
	})

	It("os-pm enablement does not change the generic checksum", func() {
		step := &sbomStep{}
		withoutOsPm := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		withOsPm := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
		Expect(withOsPm).To(Equal(withoutOsPm))
	})

	Describe("target platform", func() {
		step := &sbomStep{}

		It("differs from the platformless checksum when platform is set", func() {
			without := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "")
			with := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/amd64")
			Expect(with).NotTo(Equal(without))
		})

		It("differs between platforms", func() {
			amd64 := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/amd64")
			arm64 := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/arm64")
			Expect(amd64).NotTo(Equal(arm64))
		})

		It("is stable for the same platform", func() {
			first := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/arm64")
			second := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "", "linux/arm64")
			Expect(first).To(Equal(second))
		})

		It("changes checksum together with signer identity independently", func() {
			signedPlatformless := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:abc", "")
			signedPlatform := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:abc", "linux/amd64")
			Expect(signedPlatformless).NotTo(Equal(signedPlatform))
		})
	})
})
