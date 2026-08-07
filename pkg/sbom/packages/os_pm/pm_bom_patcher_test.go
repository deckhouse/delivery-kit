package os_pm

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PMBOMPatcher", func() {
	Describe("Apply()", func() {
		It("returns BOM unchanged when gitRepo is nil (no os-pm packages)", func(ctx context.Context) {
			patcher := &PMBOMPatcher{
				gitRepo: nil,
				commit:  "0123456789abcdef0123456789abcdef01234567",
			}
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "test-component", Version: "1.0.0"},
				},
			}

			result, err := patcher.Apply(ctx, bom)
			Expect(err).To(Succeed())
			Expect(result).To(BeIdenticalTo(bom))
			Expect(*result.Components).To(HaveLen(1))
		})

		It("returns BOM unchanged when commit is empty (no os-pm packages)", func(ctx context.Context) {
			patcher := &PMBOMPatcher{
				gitRepo: nil, // gitRepo nil is sufficient to skip
				commit:  "",
			}
			bom := &cdx.BOM{
				Components: &[]cdx.Component{
					{Name: "test-component", Version: "1.0.0"},
				},
			}

			result, err := patcher.Apply(ctx, bom)
			Expect(err).To(Succeed())
			Expect(result).To(BeIdenticalTo(bom))
		})

		It("returns BOM unchanged when BOM is nil", func(ctx context.Context) {
			patcher := &PMBOMPatcher{
				gitRepo: nil,
				commit:  "",
			}

			result, err := patcher.Apply(ctx, nil)
			Expect(err).To(Succeed())
			Expect(result).To(BeNil())
		})
	})
})
