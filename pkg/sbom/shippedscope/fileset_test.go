package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CollectFilesets", func() {
	It("lists filesets in one order however the image was read", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("var/lib/pm/files.json", `{
				"zlib": {"version": "1.3.1", "files": {}},
				"git": {"version": "2.50.1", "files": {}},
				"bash": {"version": "5.2", "files": {}}
			}`),
			regularFile("site/b-1.0.dist-info/RECORD", ""),
			regularFile("site/a-1.0.dist-info/RECORD", ""),
			regularFile("app/node_modules/y/package.json", `{"name":"y","version":"1.0.0"}`),
			regularFile("app/node_modules/x/package.json", `{"name":"x","version":"1.0.0"}`),
			regularFile("app/node_modules/x/node_modules/y/package.json", `{"name":"y","version":"0.9.0"}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		var order []string
		for _, fileset := range filesets.Filesets {
			order = append(order, string(fileset.Ecosystem)+" "+fileset.Name+" "+fileset.Version)
		}
		Expect(order).To(Equal([]string{
			"javascript x 1.0.0",
			"javascript y 0.9.0",
			"javascript y 1.0.0",
			"os-pm bash 5.2",
			"os-pm git 2.50.1",
			"os-pm zlib 1.3.1",
			"python a 1.0",
			"python b 1.0",
		}))
	})
})
