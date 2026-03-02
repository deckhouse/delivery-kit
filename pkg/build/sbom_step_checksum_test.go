package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("SbomStep Checksum", func() {
	DescribeTable("calculateStableChecksum",
		func(opts1, opts2 cyclonedxutil.MergeOpts, expectedEqual bool) {
			step := &sbomStep{}
			scanOpts := scanner.DefaultSyftScanOptions()

			cs1 := step.calculateStableChecksum(scanOpts, opts1)
			cs2 := step.calculateStableChecksum(scanOpts, opts2)

			if expectedEqual {
				Expect(cs1).To(Equal(cs2))
			} else {
				Expect(cs1).ToNot(Equal(cs2))
			}
		},

		Entry("should produce same checksum for same configuration",
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface:    gost.GostValueYes,
					SecurityFunction: gost.GostValueInherit,
				},
			},
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface:    gost.GostValueYes,
					SecurityFunction: gost.GostValueInherit,
				},
			},
			true,
		),

		Entry("should produce same checksum even if GOST configuration differs (GOST is invariant for label checksum)",
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface: gost.GostValueYes,
				},
			},
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface: gost.GostValueNo,
				},
			},
			true,
		),

		Entry("should produce same checksum when GOST inherit value is used versus other values",
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface: gost.GostValueYes,
				},
			},
			cyclonedxutil.MergeOpts{
				Gost: gost.Config{
					AttackSurface: gost.GostValueInherit,
				},
			},
			true,
		),
	)
})
