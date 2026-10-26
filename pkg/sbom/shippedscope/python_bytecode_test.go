package shippedscope

import (
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = Describe("Python bytecode evidence", func() {
	DescribeTable("retains recorded-source bytecode after deleting the source and relocating the compiled file",
		func(ctx SpecContext, filename, mode string, sourcePresent bool) {
			body, err := os.ReadFile(filepath.Join("testdata", "python_bytecode", mode+".pyc"))
			Expect(err).NotTo(HaveOccurred())
			entries := []tarEntry{
				regularFile("site/pkg-1.0.dist-info/RECORD", "pkg/module.py,,\n"),
				regularFile(filename, string(body)),
			}
			if sourcePresent {
				source, err := os.ReadFile(filepath.Join("testdata", "python_bytecode", "module.py"))
				Expect(err).NotTo(HaveOccurred())
				entries = append(entries, regularFile("site/pkg/module.py", string(source)))
			}
			image, err := imageOf(entries)
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, image)
			Expect(err).NotTo(HaveOccurred())
			Expect(filesetOf(filesets, EcosystemPython, "pkg", "1.0").Files).To(HaveKey("/" + filename))
			bom := cyclonedxutil.NewBOM()
			bom.Components = &[]cdx.Component{{PackageURL: "pkg:pypi/pkg@1.0", Name: "pkg", Version: "1.0"}}
			RecordOccurrences(bom, filesets.Filesets)
			Expect(MarkNotShipped(ctx, bom, filesets)).To(BeZero())

			for _, target := range []string{"app/renamed.pyc", "another/copy.pyc"} {
				bom, err = cyclonedxutil.CloneBOM(bom)
				Expect(err).NotTo(HaveOccurred())
				imported, err := imageOf([]tarEntry{regularFile(target, string(body))})
				Expect(err).NotTo(HaveOccurred())
				importedFiles, err := CollectFilesets(ctx, imported)
				Expect(err).NotTo(HaveOccurred())
				RecordOccurrences(bom, importedFiles.Filesets)
				Expect(MarkNotShipped(ctx, bom, importedFiles)).To(BeZero())
			}
			Expect(MarkNotShipped(ctx, bom, filesetsOf(emptyIndex()))).To(Equal(1))
		},
		Entry("legacy timestamp after source removal", "site/pkg/module.pyc", "timestamp", false),
		Entry("legacy checked hash after source removal", "site/pkg/module.pyc", "checked", false),
		Entry("legacy unchecked hash after source removal", "site/pkg/module.pyc", "unchecked", false),
		Entry("legacy beside its source before import", "site/pkg/module.pyc", "checked", true),
		Entry("existing cache location after source removal", "site/pkg/__pycache__/module.cpython-314.pyc", "checked", false),
		Entry("existing optimized cache location", "site/pkg/__pycache__/module.cpython-314.opt-2.pyc", "unchecked", false),
	)

	DescribeTable("uses the exact RECORD ownership boundary rather than the bytecode basename",
		func(ctx SpecContext, record, bytecode string, expected bool) {
			image, err := imageOf([]tarEntry{
				regularFile("site/pkg-1.0.dist-info/RECORD", record),
				regularFile(bytecode, "payload"),
			})
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, image)
			Expect(err).NotTo(HaveOccurred())
			_, found := filesetOf(filesets, EcosystemPython, "pkg", "1.0").Files["/"+bytecode]
			Expect(found).To(Equal(expected))
		},
		Entry("dotted legacy stem", "pkg/foo.bar.py,,\n", "site/pkg/foo.bar.pyc", true),
		Entry("dotted stem is not its first component", "pkg/foo.py,,\n", "site/pkg/foo.bar.pyc", false),
		Entry("namespace sibling belongs to another distribution", "ns/first.py,,\n", "site/ns/second.pyc", false),
		Entry("same basename elsewhere is not a declared sibling", "pkg/module.py,,\n", "other/module.pyc", false),
		Entry("an unrelated declared file cannot claim bytecode", "pkg/module.txt,,\n", "site/pkg/module.pyc", false),
		Entry("bytecode without a declared source is not attributed", "", "site/pkg/module.pyc", false),
		Entry("explicit bytecode declaration remains supported", "pkg/module.pyc,,\n", "site/pkg/module.pyc", true),
		Entry("legacy filename containing an optimization-like word", "pkg/my.opt-1.py,,\n", "site/pkg/my.opt-1.pyc", true),
		Entry("unrecognized suffix is not inferred", "pkg/module.py,,\n", "site/pkg/module.pyc.bak", false),
		Entry("old optimized suffix requires an explicit declaration", "pkg/module.py,,\n", "site/pkg/module.pyo", false),
		Entry("explicit old optimized suffix remains a declared file", "pkg/module.pyo,,\n", "site/pkg/module.pyo", true),
	)

	It("uses the layer-owned content behind a legacy bytecode hardlink", func(ctx SpecContext) {
		image, err := imageOf([]tarEntry{
			regularFile("payload/compiled", "original compiled payload"),
			hardlink("site/pkg/module.pyc", "payload/compiled"),
			regularFile("site/pkg-1.0.dist-info/RECORD", "pkg/module.py,,\n"),
		}, []tarEntry{regularFile("payload/compiled", "replacement")})
		Expect(err).NotTo(HaveOccurred())
		filesets, err := CollectFilesets(ctx, image)
		Expect(err).NotTo(HaveOccurred())
		file := filesetOf(filesets, EcosystemPython, "pkg", "1.0").Files["/site/pkg/module.pyc"]
		Expect(file.Digest).To(Equal(digestOf("original compiled payload")))
	})
})
