package declared

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GoModGraphEdges", func() {
	golang := func(ref, module, version string) cdx.Component {
		return cdx.Component{BOMRef: ref, PackageURL: "pkg:golang/" + module + "@" + version}
	}

	It("collapses the unpruned graph onto the selected versions", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			golang("cobra", "github.com/spf13/cobra", "v1.8.0"),
			golang("pflag", "github.com/spf13/pflag", "v1.0.5"),
			golang("text", "golang.org/x/text", "v0.14.0"),
		}}
		graph := []byte(`example.com/app github.com/spf13/cobra@v1.8.0
example.com/app golang.org/x/text@v0.14.0
example.com/app go@1.22
github.com/spf13/cobra@v1.8.0 github.com/spf13/pflag@v1.0.5
github.com/spf13/cobra@v1.8.0 github.com/cpuguy83/go-md2man/v2@v2.0.3
github.com/spf13/cobra@v1.8.0 golang.org/x/text@v0.3.0
github.com/spf13/cobra@v1.7.0 github.com/spf13/pflag@v1.0.4
github.com/spf13/pflag@v1.0.5 go@1.12
golang.org/x/text@v0.14.0 golang.org/x/tools@v0.6.0
`)

		deps, err := GoModGraphEdges(bom, graph)
		Expect(err).NotTo(HaveOccurred())
		Expect(deps).To(Equal([]cdx.Dependency{
			{Ref: "cobra", Dependencies: &[]string{"pflag", "text"}},
		}), "cobra@v1.7.0 is not selected; go-md2man and x/tools are not in the build; text@v0.3.0 collapses onto v0.14.0; main-module edges are declared from go.mod")
	})

	It("matches module paths case-insensitively", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			golang("toml", "github.com/burntsushi/toml", "v1.6.0"),
			golang("lo", "github.com/samber/lo", "v1.47.0"),
		}}
		deps, err := GoModGraphEdges(bom, []byte("github.com/samber/lo@v1.47.0 github.com/BurntSushi/toml@v1.6.0\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(deps).To(Equal([]cdx.Dependency{{Ref: "lo", Dependencies: &[]string{"toml"}}}))
	})

	It("drops an edge that collapses onto its own source", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{golang("lo", "github.com/samber/lo", "v1.47.0")}}
		deps, err := GoModGraphEdges(bom, []byte("github.com/samber/lo@v1.47.0 github.com/samber/lo@v1.40.0\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(deps).To(BeEmpty())
	})

	It("rejects a malformed line", func() {
		_, err := GoModGraphEdges(&cdx.BOM{}, []byte("garbage\n"))
		Expect(err).To(MatchError(ContainSubstring("parse go mod graph line")))
	})

	It("returns nothing for an empty graph", func() {
		deps, err := GoModGraphEdges(&cdx.BOM{}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(deps).To(BeEmpty())
	})
})
