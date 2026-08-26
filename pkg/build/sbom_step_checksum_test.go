package build

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("SbomStep Checksum", func() {
	type checksumInputs struct {
		scanOpts       scanner.ScanOptions
		mergeOpts      cyclonedxutil.MergeOpts
		signerIdentity string
		targetPlatform string
	}

	baseline := func() checksumInputs {
		return checksumInputs{
			scanOpts:  scanner.ScanOptions{},
			mergeOpts: cyclonedxutil.MergeOpts{},
		}
	}

	checksumOf := func(in checksumInputs) string {
		step := &sbomStep{}
		return step.calculateStableChecksum(in.scanOpts, in.mergeOpts, in.signerIdentity, in.targetPlatform)
	}

	It("same inputs produce same checksum", func() {
		Expect(checksumOf(baseline())).To(Equal(checksumOf(baseline())))
	})

	DescribeTable("changes when a single input changes",
		func(mutate func(in *checksumInputs)) {
			mutated := baseline()
			mutate(&mutated)
			Expect(checksumOf(mutated)).NotTo(Equal(checksumOf(baseline())))
		},
		Entry("scan options", func(in *checksumInputs) {
			in.scanOpts = scanner.ScanOptions{Commands: []scanner.ScanCommand{{SourcePath: "image"}}}
		}),
		Entry("merge options: base BOM", func(in *checksumInputs) {
			in.mergeOpts.BaseBOM = &cdx.BOM{
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_6,
				Components:  &[]cdx.Component{{Name: "base-lib", Version: "1.0.0"}},
			}
		}),
		Entry("gost attack surface", func(in *checksumInputs) {
			in.mergeOpts.Gost.AttackSurface = gost.GostValueYes
		}),
		Entry("gost security function", func(in *checksumInputs) {
			in.mergeOpts.Gost.SecurityFunction = gost.GostValueIndirect
		}),
		Entry("signer identity", func(in *checksumInputs) {
			in.signerIdentity = "signer:abc"
		}),
		Entry("target platform", func(in *checksumInputs) {
			in.targetPlatform = "linux/amd64"
		}),
	)

	It("GOST config changes checksum even without base and import BOMs", func() {
		withGost := baseline()
		withGost.mergeOpts.Gost = gost.Config{
			AttackSurface:    gost.GostValueYes,
			SecurityFunction: gost.GostValueIndirect,
		}

		Expect(withGost.mergeOpts.IsEmpty()).To(BeTrue())
		Expect(checksumOf(withGost)).NotTo(Equal(checksumOf(baseline())))
	})

	It("different signer identities produce different checksums", func() {
		first := baseline()
		first.signerIdentity = "signer:key1"

		second := baseline()
		second.signerIdentity = "signer:key2"

		Expect(checksumOf(first)).NotTo(Equal(checksumOf(second)))
	})

	It("format version change invalidates cache", func() {
		Expect(checksumOf(baseline())).NotTo(Equal("aa969eabe2faad149265a94e60b173e527e0bc27898afcd0ec4e85a06b28f29b"),
			"checksum must differ from format-v1 era (before format version was added)")
	})

	Describe("target platform", func() {
		It("differs between platforms", func() {
			amd64 := baseline()
			amd64.targetPlatform = "linux/amd64"

			arm64 := baseline()
			arm64.targetPlatform = "linux/arm64"

			Expect(checksumOf(amd64)).NotTo(Equal(checksumOf(arm64)))
		})

		It("is stable for the same platform", func() {
			platform := baseline()
			platform.targetPlatform = "linux/arm64"

			Expect(checksumOf(platform)).To(Equal(checksumOf(platform)))
		})

		It("changes checksum independently of signer identity", func() {
			signedPlatformless := baseline()
			signedPlatformless.signerIdentity = "signer:abc"

			signedPlatform := signedPlatformless
			signedPlatform.targetPlatform = "linux/amd64"

			Expect(checksumOf(signedPlatformless)).NotTo(Equal(checksumOf(signedPlatform)))
		})
	})

	Describe("part encoding", func() {
		It("does not collide when a part value absorbs a slot boundary", func() {
			// A separator-joined encoding maps both of these onto the same input:
			// "...-a-b" from a single part "a-b", and "...-a-b" from parts "a" and "b".
			joinedIntoSigner := baseline()
			joinedIntoSigner.signerIdentity = "a-b"

			splitAcrossParts := baseline()
			splitAcrossParts.signerIdentity = "a"
			splitAcrossParts.targetPlatform = "b"

			Expect(checksumOf(joinedIntoSigner)).NotTo(Equal(checksumOf(splitAcrossParts)))
		})

		It("does not collide when the same value moves between adjacent parts", func() {
			asSigner := baseline()
			asSigner.signerIdentity = "linux/amd64"

			asPlatform := baseline()
			asPlatform.targetPlatform = "linux/amd64"

			Expect(checksumOf(asSigner)).NotTo(Equal(checksumOf(asPlatform)))
		})

		It("yields pairwise distinct checksums across single-input flips", func() {
			flips := map[string]checksumInputs{"baseline": baseline()}

			scanFlip := baseline()
			scanFlip.scanOpts = scanner.ScanOptions{Commands: []scanner.ScanCommand{{SourcePath: "image"}}}
			flips["scan"] = scanFlip

			gostFlip := baseline()
			gostFlip.mergeOpts.Gost.AttackSurface = gost.GostValueYes
			flips["gost"] = gostFlip

			signerFlip := baseline()
			signerFlip.signerIdentity = "signer:abc"
			flips["signer"] = signerFlip

			platformFlip := baseline()
			platformFlip.targetPlatform = "linux/arm64"
			flips["platform"] = platformFlip

			seen := map[string]string{}
			for name, in := range flips {
				sum := checksumOf(in)
				Expect(seen).NotTo(HaveKey(sum), "checksum of %q collides with %q", name, seen[sum])
				seen[sum] = name
			}
		})
	})
})
