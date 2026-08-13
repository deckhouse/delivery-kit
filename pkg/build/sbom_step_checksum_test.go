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
		plain := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "")
		withGost := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{
			Gost: gost.Config{
				AttackSurface:    gost.GostValueYes,
				SecurityFunction: gost.GostValueIndirect,
			},
		}, "")
		Expect(plain).To(Equal(withGost))
	})

	It("same inputs produce same checksum", func() {
		step := &sbomStep{}
		a := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "")
		b := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "")
		Expect(a).To(Equal(b))
	})

	It("signer identity changes checksum", func() {
		step := &sbomStep{}
		unsigned := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "")
		signed := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:abc")
		Expect(unsigned).NotTo(Equal(signed))
	})

	It("different signer identities produce different checksums", func() {
		step := &sbomStep{}
		a := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:key1")
		b := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "signer:key2")
		Expect(a).NotTo(Equal(b))
	})

	It("format version change invalidates cache", func() {
		step := &sbomStep{}
		checksum := step.calculateStableChecksum(scanner.ScanOptions{}, cyclonedxutil.MergeOpts{}, "")
		Expect(checksum).NotTo(Equal("aa969eabe2faad149265a94e60b173e527e0bc27898afcd0ec4e85a06b28f29b"),
			"checksum must differ from format-v1 era (before format version was added)")
	})
})
