package scanner

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

var _ = Describe("ScanOptions", func() {
	Describe("DefaultSyftScanOptions()", func() {
		It("should work", func() {
			Expect(DefaultSyftScanOptions()).To(Equal(ScanOptions{
				Image:      "anchore/syft:v1.45.1",
				PullPolicy: PullIfMissing,
				Commands: []ScanCommand{
					NewSyftScanCommand(),
				},
			}))
		})
	})

	DescribeTable("Checksum()",
		func(scanOpts ScanOptions, expected types.GomegaMatcher) {
			Expect(scanOpts.Checksum()).To(expected)
		},
		Entry(
			"should work for DefaultSyftScanOptions",
			DefaultSyftScanOptions(),
			Equal("484f86a01a9d3fd57238e2ad0b73fbf31098d3c53c52909267638fbdfd5e9d72"),
		),
	)
})
