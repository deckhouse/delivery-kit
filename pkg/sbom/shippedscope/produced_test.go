package shippedscope

import (
	"bytes"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/werf"
)

var _ = ginkgo.BeforeEach(func() {
	gomega.Expect(werf.Init(ginkgo.GinkgoT().TempDir(), "")).To(gomega.Succeed())
})

var _ = ginkgo.Describe("CollectProducedFiles", func() {
	ginkgo.It("returns unknown when the layer attribution is unknown", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("bin/app", string(goBinary()))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: false})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeFalse())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("returns checked-empty when attribution is known and no ranges are eligible", func(ctx ginkgo.SpecContext) {
		img, err := imageOf([]tarEntry{regularFile("bin/app", string(goBinary()))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{Known: true, Ranges: nil})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("collects a binary added in a produced range", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(binary))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Path).To(gomega.Equal("/bin/app"))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(string(binary))))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictNames))
	})

	ginkgo.It("ignores non-binary files in produced ranges", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/base", "base")},
			[]tarEntry{regularFile("etc/config", "config"), regularFile("app.sh", "#!/bin/sh\necho hi\n")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("excludes a binary added in a produced range but deleted by a later layer", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(binary))},
			[]tarEntry{whiteout("bin/.wh.app")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("excludes a binary whose content was replaced by a later layer", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(binary))},
			[]tarEntry{regularFile("bin/app", "replaced")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("keeps a binary whose path was renamed but bytes survive elsewhere", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(binary))},
			[]tarEntry{
				whiteout("bin/.wh.app"),
				regularFile("bin/renamed", string(binary)),
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(string(binary))))
	})

	ginkgo.It("collects binaries from multiple produced ranges", func(ctx ginkgo.SpecContext) {
		binaryA := goBinary()
		binaryB := goTestingLinkedBinary()
		gomega.Expect(binaryA).NotTo(gomega.Equal(binaryB))

		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app1", string(binaryA))},
			[]tarEntry{regularFile("lib/import.so", "imported")},
			[]tarEntry{regularFile("bin/app2", string(binaryB))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known: true,
			Ranges: []ProducedLayerRange{
				{Start: 1, End: 2},
				{Start: 3, End: 4},
			},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(2))
	})

	ginkgo.It("deduplicates identical binary content across ranges", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app1", string(binary))},
			[]tarEntry{regularFile("lib/import.so", "imported")},
			[]tarEntry{regularFile("bin/app2", string(binary))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known: true,
			Ranges: []ProducedLayerRange{
				{Start: 1, End: 2},
				{Start: 3, End: 4},
			},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		digests := make(map[string]bool)
		for _, f := range produced.Files {
			digests[f.Digest] = true
		}
		gomega.Expect(digests).To(gomega.HaveLen(1))
	})

	ginkgo.It("collects a binary surviving via hardlink when the original target is replaced", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{
				regularFile("bin/app", string(binary)),
				hardlink("bin/app.link", "bin/app"),
			},
			[]tarEntry{regularFile("bin/app", "replaced")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(string(binary))))
	})

	ginkgo.It("collects a binary via hardlink when the link alone makes it survive", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{
				regularFile("bin/app", string(binary)),
				hardlink("bin/backup", "bin/app"),
			},
			[]tarEntry{whiteout("bin/.wh.app")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(string(binary))))
	})

	ginkgo.It("handles a produced range spanning multiple layers within one stage", func(ctx ginkgo.SpecContext) {
		binaryA := goBinary()
		binaryB := goTestingLinkedBinary()
		gomega.Expect(binaryA).NotTo(gomega.Equal(binaryB))

		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/part1", string(binaryA))},
			[]tarEntry{regularFile("bin/part2", string(binaryB))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 3}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(2))
	})

	ginkgo.It("counts a binary copied to a new path by an eligible stage", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("bin/base", string(binary))},
			[]tarEntry{regularFile("bin/copy", string(binary))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1), "a new path in the stage filesystem is an addition even if the bytes existed elsewhere")
	})

	ginkgo.It("collects a file that overwrites existing path with different binary content", func(ctx ginkgo.SpecContext) {
		binaryA := goBinary()
		binaryB := goTestingLinkedBinary()
		gomega.Expect(binaryA).NotTo(gomega.Equal(binaryB))

		img, err := imageOf(
			[]tarEntry{regularFile("bin/app", string(binaryA))},
			[]tarEntry{regularFile("bin/app", string(binaryB))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Digest).To(gomega.Equal(digestOf(string(binaryB))))
	})

	ginkgo.It("validates layer range bounds", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(goBinary()))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		_, err = CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 0, End: 10}},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
	})

	ginkgo.It("validates inverted range bounds", func(ctx ginkgo.SpecContext) {
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/app", string(goBinary()))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		_, err = CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 2, End: 1}},
		})
		gomega.Expect(err).To(gomega.HaveOccurred())
	})

	ginkgo.It("returns deterministic output order", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{
				regularFile("bin/z", string(binary)),
				regularFile("bin/a", string(goTestingLinkedBinary())),
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		layers := ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		}

		var orders [][]string
		for range 5 {
			produced, err := CollectProducedFiles(ctx, img, index, layers)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			var paths []string
			for _, f := range produced.Files {
				paths = append(paths, f.Path)
			}
			orders = append(orders, paths)
		}

		for i := 1; i < len(orders); i++ {
			gomega.Expect(orders[i]).To(gomega.Equal(orders[0]))
		}
	})

	ginkgo.It("does not treat test binaries as produced evidence", func(ctx ginkgo.SpecContext) {
		testBinary := goTestBinary()
		img, err := imageOf(
			[]tarEntry{regularFile("etc/config", "config")},
			[]tarEntry{regularFile("bin/test", string(testBinary))},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 1, End: 2}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeTrue())
		gomega.Expect(produced.Files).To(gomega.BeEmpty())
	})

	ginkgo.It("returns unknown when the file index is incomplete due to unresolved hardlinks", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{
				regularFile("bin/app", string(binary)),
				hardlink("bin/link", "bin/absent"),
			},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Incomplete).To(gomega.BeTrue())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 0, End: 1}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Known).To(gomega.BeFalse())
	})
})

var _ = ginkgo.Describe("CollectProducedFiles classification", func() {
	ginkgo.It("classifies a Go binary with its modules", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf([]tarEntry{regularFile("bin/app", string(binary))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 0, End: 1}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictNames))
		gomega.Expect(produced.Files[0].Classification.Modules).To(gomega.ContainElement("example.test/lib"))
	})

	ginkgo.It("classifies binaries with unknown go/rust evidence", func(ctx ginkgo.SpecContext) {
		wasmBinary := goBinaryFor("js/wasm")
		img, err := imageOf([]tarEntry{regularFile("bin/app.wasm", string(wasmBinary))})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 0, End: 1}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictUnknown))
	})

	ginkgo.It("correctly handles hardlink-only surviving binary content for classification", func(ctx ginkgo.SpecContext) {
		binary := goBinary()
		img, err := imageOf(
			[]tarEntry{
				regularFile("bin/app", string(binary)),
				hardlink("bin/backup", "bin/app"),
			},
			[]tarEntry{whiteout("bin/.wh.app")},
		)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, err := IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		produced, err := CollectProducedFiles(ctx, img, index, ProducedLayers{
			Known:  true,
			Ranges: []ProducedLayerRange{{Start: 0, End: 1}},
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(produced.Files).To(gomega.HaveLen(1))
		gomega.Expect(produced.Files[0].Classification.Go).To(gomega.Equal(VerdictNames))
		gomega.Expect(produced.Files[0].Classification.Modules).To(gomega.ContainElement("example.test/lib"))
	})
})

var _ = ginkgo.Describe("binary detection helpers", func() {
	ginkgo.DescribeTable("formatOf identifies executable formats",
		func(header []byte, expectExecutable bool) {
			format, executable, err := formatOf(bytes.NewReader(header))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			if expectExecutable {
				gomega.Expect(executable).To(gomega.BeTrue())
				gomega.Expect(format).NotTo(gomega.BeEmpty())
			} else {
				gomega.Expect(executable).To(gomega.BeFalse())
			}
		},
		ginkgo.Entry("ELF binary", []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, true),
		ginkgo.Entry("Mach-O 64-bit", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, true),
		ginkgo.Entry("PE binary", []byte{'M', 'Z', 0, 0, 0, 0, 0, 0}, true),
		ginkgo.Entry("Shell script", []byte("#!/bin/sh\n"), false),
		ginkgo.Entry("JSON config", []byte(`{"key": "value"}`), false),
		ginkgo.Entry("Empty file", []byte{}, false),
	)
})
