package build

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("SBOM binary merge wiring", func() {
	var target, inherited *cdx.BOM
	var filesets *shippedscope.Filesets

	ginkgo.BeforeEach(func() {
		target = cyclonedxutil.NewBOM()
		target.Components = &[]cdx.Component{{Name: "example.com/module", PackageURL: "pkg:golang/example.com/module@v1.0.0"}}
		var err error
		inherited, err = cyclonedxutil.CloneBOM(target)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		filesets = &shippedscope.Filesets{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}}}
	})

	ginkgo.It("does not turn an unknown inherited origin into the fresh target's checked-empty verdict", func(ctx ginkgo.SpecContext) {
		original, err := cyclonedxutil.CloneBOM(inherited)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		produced := &shippedscope.ProducedFiles{Known: true}
		opts, err := prepareBinaryMerge(ctx, target, cyclonedxutil.MergeOpts{BaseBOM: inherited}, produced)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		merged, err := cyclonedxutil.MergeBOMs(ctx, target, opts)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		recordShippedScope(ctx, merged, filesets, produced, "app")

		gomega.Expect(inherited).To(gomega.Equal(original))
		gomega.Expect(*merged.Components).To(gomega.HaveLen(1))
		gomega.Expect(lo.FromPtr((*merged.Components)[0].Properties)).To(gomega.ContainElement(cdx.Property{Name: "werf:binaries", Value: "unknown"}))
		gomega.Expect(lo.FromPtr((*merged.Components)[0].Properties)).NotTo(gomega.ContainElement(cdx.Property{Name: "werf:shipped", Value: "false"}))
	})

	ginkgo.It("marks a fresh module when a complete build produced no binary", func(ctx ginkgo.SpecContext) {
		produced := &shippedscope.ProducedFiles{Known: true}
		opts, err := prepareBinaryMerge(ctx, target, cyclonedxutil.MergeOpts{}, produced)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(opts.IsEmpty()).To(gomega.BeTrue())
		recordShippedScope(ctx, target, filesets, produced, "app")
		gomega.Expect(lo.FromPtr((*target.Components)[0].Properties)).To(gomega.ContainElement(cdx.Property{Name: "werf:shipped", Value: "false"}))
	})

	ginkgo.It("clears inherited negative binary verdicts when reading the current image fails", func(ctx ginkgo.SpecContext) {
		(*inherited.Components)[0].Properties = &[]cdx.Property{
			{Name: "werf:binaries", Value: "none"},
			{Name: "werf:shipped", Value: "false"},
		}
		recordShippedScope(ctx, inherited, nil, &shippedscope.ProducedFiles{}, "app")
		gomega.Expect(lo.FromPtr((*inherited.Components)[0].Properties)).To(gomega.ContainElement(cdx.Property{Name: "werf:binaries", Value: "unknown"}))
		gomega.Expect(lo.FromPtr((*inherited.Components)[0].Properties)).NotTo(gomega.ContainElement(cdx.Property{Name: "werf:shipped", Value: "false"}))
	})
})
