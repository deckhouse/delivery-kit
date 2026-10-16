package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CollectFilesets, JavaScript", func() {
	It("leaves a nested package out of the tree that holds it", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/express/package.json", `{"name":"express","version":"4.21.2"}`),
			regularFile("app/node_modules/express/lib/router.js", "router"),
			regularFile("app/node_modules/express/node_modules/debug/package.json", `{"name":"debug","version":"2.6.9"}`),
			regularFile("app/node_modules/express/node_modules/debug/src/index.js", "debug"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		express := filesetOf(filesets, EcosystemJavaScript, "express", "4.21.2")
		Expect(express).NotTo(BeNil())
		Expect(express.Files).To(HaveKey("/app/node_modules/express/lib/router.js"))
		Expect(express.Files).NotTo(HaveKey("/app/node_modules/express/node_modules/debug/src/index.js"))

		debug := filesetOf(filesets, EcosystemJavaScript, "debug", "2.6.9")
		Expect(debug).NotTo(BeNil())
		Expect(debug.Files).To(HaveKey("/app/node_modules/express/node_modules/debug/src/index.js"))
	})

	It("takes the name the package declares, not the directory it sits in", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/@babel/core/package.json", `{"name":"@babel/core","version":"7.28.0"}`),
			regularFile("app/node_modules/@babel/core/lib/index.js", "babel"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		babel := filesetOf(filesets, EcosystemJavaScript, "@babel/core", "7.28.0")
		Expect(babel).NotTo(BeNil())
		Expect(babel.Files).To(HaveKey("/app/node_modules/@babel/core/lib/index.js"))
	})

	It("takes packages a distribution installs outside node_modules", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/share/nodejs/semver/package.json", `{"name":"semver","version":"7.6.3"}`),
			regularFile("usr/share/nodejs/semver/index.js", "semver"),
			regularFile("usr/lib/nodejs/@types/node/package.json", `{"name":"@types/node","version":"22.0.0"}`),
			regularFile("usr/lib/nodejs/@types/node/index.d.ts", "types"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		semver := filesetOf(filesets, EcosystemJavaScript, "semver", "7.6.3")
		Expect(semver).NotTo(BeNil())
		Expect(semver.Files).To(HaveKey("/usr/share/nodejs/semver/index.js"))

		types := filesetOf(filesets, EcosystemJavaScript, "@types/node", "22.0.0")
		Expect(types).NotTo(BeNil())
		Expect(types.Files).To(HaveKey("/usr/lib/nodejs/@types/node/index.d.ts"))
	})

	It("leaves a fixture a package ships inside its own tree to that package", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/resolve/package.json", `{"name":"resolve","version":"1.22.8"}`),
			regularFile("app/node_modules/resolve/test/resolver/baz/package.json", `{"name":"baz","version":"1.0.0"}`),
			regularFile("app/node_modules/resolve/test/resolver/baz/quux.js", "fixture"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesetOf(filesets, EcosystemJavaScript, "baz", "1.0.0")).To(BeNil())

		resolve := filesetOf(filesets, EcosystemJavaScript, "resolve", "1.22.8")
		Expect(resolve).NotTo(BeNil())
		Expect(resolve.Files).To(HaveKey("/app/node_modules/resolve/test/resolver/baz/quux.js"))
	})

	It("tells a nested package tree from a directory whose name merely ends the same way", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/webpack/package.json", `{"name":"webpack","version":"5.95.0"}`),
			regularFile("app/node_modules/webpack/lib/my_node_modules/plugin.js", "plugin"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		webpack := filesetOf(filesets, EcosystemJavaScript, "webpack", "5.95.0")
		Expect(webpack).NotTo(BeNil())
		Expect(webpack.Files).To(HaveKey("/app/node_modules/webpack/lib/my_node_modules/plugin.js"))
	})

	It("keeps a package.json that belongs to no package tree out of the filesets", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/package.json", `{"name":"my-app","version":"1.0.0"}`),
			regularFile("app/index.js", "app"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesetOf(filesets, EcosystemJavaScript, "my-app", "1.0.0")).To(BeNil())
	})

	It("keeps the symlinks a package tree holds", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/semver/package.json", `{"name":"semver","version":"7.6.3"}`),
			symlink("app/node_modules/semver/bin/semver", "../index.js"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		semver := filesetOf(filesets, EcosystemJavaScript, "semver", "7.6.3")
		Expect(semver).NotTo(BeNil())
		Expect(semver.Symlinks).To(HaveKeyWithValue("/app/node_modules/semver/bin/semver", "../index.js"))
	})

	It("ignores a package declaring neither name nor version", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("app/node_modules/broken/package.json", `{"description":"no name here"}`),
			regularFile("app/node_modules/broken/index.js", "broken"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets.Filesets).To(BeEmpty())
	})
})
