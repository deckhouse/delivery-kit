package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const cjsonRockManifest = `rock_manifest = {
   bin = {
      ["lua-cjson"] = "9f8c1a"
   },
   doc = {
      ["README.md"] = "2b7e4d"
   },
   lib = {
      ["cjson.so"] = "a1b2c3"
   },
   lua = {
      cjson = {
         ["util.lua"] = "d4e5f6"
      }
   },
   ["lua-cjson-2.1.0-1.rockspec"] = "7a8b9c"
}
`

var _ = Describe("CollectFilesets, Lua", func() {
	It("spreads a rock over the install roots its manifest names", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/rock_manifest", cjsonRockManifest),
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/lua-cjson-2.1.0-1.rockspec", "spec"),
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/doc/README.md", "readme"),
			regularFile("usr/local/bin/lua-cjson", "launcher"),
			regularFile("usr/local/lib/lua/5.4/cjson.so", "native"),
			regularFile("usr/local/share/lua/5.4/cjson/util.lua", "util"),
			regularFile("usr/local/share/lua/5.4/other.lua", "not ours"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		cjson := filesetOf(filesets, EcosystemLua, "lua-cjson", "2.1.0-1")
		Expect(cjson).NotTo(BeNil())
		Expect(cjson.Files).To(HaveKey("/usr/local/bin/lua-cjson"))
		Expect(cjson.Files).To(HaveKey("/usr/local/lib/lua/5.4/cjson.so"))
		Expect(cjson.Files).To(HaveKey("/usr/local/share/lua/5.4/cjson/util.lua"))
		Expect(cjson.Files).NotTo(HaveKey("/usr/local/share/lua/5.4/other.lua"))
	})

	It("keeps the files the manifest names beside itself in the rock directory", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/rock_manifest", cjsonRockManifest),
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/lua-cjson-2.1.0-1.rockspec", "spec"),
			regularFile("usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/doc/README.md", "readme"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		cjson := filesetOf(filesets, EcosystemLua, "lua-cjson", "2.1.0-1")
		Expect(cjson.Files).To(HaveKey("/usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/lua-cjson-2.1.0-1.rockspec"))
		Expect(cjson.Files).To(HaveKey("/usr/local/lib/luarocks/rocks-5.4/lua-cjson/2.1.0-1/doc/README.md"))
	})

	It("takes the lua version of the tree the rock was installed into", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/luarocks/rocks-5.1/luafilesystem/1.8.0-1/rock_manifest",
				"rock_manifest = {\n   lib = {\n      [\"lfs.so\"] = \"aaa\"\n   }\n}\n"),
			regularFile("usr/lib/lua/5.1/lfs.so", "native"),
			regularFile("usr/lib/lua/5.4/lfs.so", "another tree"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		lfs := filesetOf(filesets, EcosystemLua, "luafilesystem", "1.8.0-1")
		Expect(lfs.Files).To(HaveKey("/usr/lib/lua/5.1/lfs.so"))
		Expect(lfs.Files).NotTo(HaveKey("/usr/lib/lua/5.4/lfs.so"))
	})

	It("ignores a manifest it cannot read", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/local/lib/luarocks/rocks-5.4/broken/1.0-1/rock_manifest", "this is not a lua table"),
			regularFile("usr/local/share/lua/5.4/broken.lua", "code"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets).To(BeEmpty())
	})
})
