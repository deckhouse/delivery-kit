package shippedscope

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

const (
	bytecodeRockManifest = "usr/local/lib/luarocks/rocks-5.4/pkg/1.0-1/rock_manifest"
	bytecodeRockModules  = "usr/local/share/lua/5.4/"

	luaBytecodeRockManifest = `rock_manifest = {
   lua = {
      pkg = {
         ["init.lua"] = "a1",
         ["util.lua"] = "b2"
      },
      ["top.lua"] = "c3"
   }
}
`
)

var _ = ginkgo.Describe("Lua bytecode evidence", func() {
	ginkgo.DescribeTable("attributes compiled siblings of a declared module by the path the rock declared",
		func(ctx ginkgo.SpecContext, source string, sourcePresent bool, bytecode string, expected bool) {
			entries := []tarEntry{
				regularFile(bytecodeRockManifest, luaBytecodeRockManifest),
				regularFile(bytecodeRockModules+bytecode, "compiled"),
			}
			if sourcePresent {
				entries = append(entries, regularFile(bytecodeRockModules+source, "source"))
			}
			filesets := collectFilesetsOf(ctx, entries)
			rock := filesetOf(filesets, EcosystemLua, "pkg", "1.0-1")
			gomega.Expect(rock).NotTo(gomega.BeNil())
			_, found := rock.Files["/"+bytecodeRockModules+bytecode]
			gomega.Expect(found).To(gomega.Equal(expected))
			if sourcePresent {
				gomega.Expect(rock.Files).To(gomega.HaveKey("/" + bytecodeRockModules + source))
			}
		},
		ginkgo.Entry("luac after source removal", "pkg/util.lua", false, "pkg/util.luac", true),
		ginkgo.Entry("ljbc after source removal", "pkg/util.lua", false, "pkg/util.ljbc", true),
		ginkgo.Entry("luac beside its kept source", "pkg/util.lua", true, "pkg/util.luac", true),
		ginkgo.Entry("module directory init", "pkg/init.lua", false, "pkg/init.luac", true),
		ginkgo.Entry("top-level module", "top.lua", false, "top.ljbc", true),
		ginkgo.Entry("same stem in another directory", "pkg/util.lua", false, "other/util.luac", false),
		ginkgo.Entry("same stem in a nested directory", "pkg/util.lua", false, "pkg/sub/util.luac", false),
		ginkgo.Entry("unrecognized lc suffix", "pkg/util.lua", false, "pkg/util.lc", false),
		ginkgo.Entry("unrecognized out suffix", "pkg/util.lua", false, "pkg/util.out", false),
		ginkgo.Entry("sibling of an undeclared module", "pkg/util.lua", false, "pkg/other.luac", false),
	)

	ginkgo.It("keeps a rock shipped by its compiled module alone after a relocating import", func(ctx ginkgo.SpecContext) {
		donorFiles := collectFilesetsOf(ctx, []tarEntry{
			regularFile(bytecodeRockManifest, luaBytecodeRockManifest),
			regularFile(bytecodeRockModules+"pkg/util.luac", "compiled util"),
		})
		gomega.Expect(filesetOf(donorFiles, EcosystemLua, "pkg", "1.0-1").Files).To(gomega.HaveKey("/" + bytecodeRockModules + "pkg/util.luac"))
		donor := cyclonedxutil.NewBOM()
		donor.Components = &[]cdx.Component{componentOf("pkg:luarocks/pkg@1.0-1")}
		RecordOccurrences(ctx, donor, donorFiles.Filesets)
		gomega.Expect(MarkNotShipped(ctx, donor, donorFiles)).To(gomega.BeZero())

		consumer, err := cyclonedxutil.CloneBOM(donor)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		importedFiles := collectFilesetsOf(ctx, []tarEntry{regularFile("app/util.luac", "compiled util")})
		RecordOccurrences(ctx, consumer, importedFiles.Filesets)
		gomega.Expect(MarkNotShipped(ctx, consumer, importedFiles)).To(gomega.BeZero())

		empty, err := cyclonedxutil.CloneBOM(donor)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(MarkNotShipped(ctx, empty, filesetsOf(emptyIndex()))).To(gomega.Equal(1))
	})
})
