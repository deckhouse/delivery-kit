package shippedscope

import (
	"bytes"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

var _ = ginkgo.Describe("CollectFilesets, Yarn Plug'n'Play", func() {
	const (
		msArchive      = "ms 2.1.3 archive"
		babelArchive   = "@babel/core 7.28.0 archive"
		debug2Archive  = "debug 2.6.9 archive"
		debug4Archive  = "debug 4.3.4 archive"
		msCachePath    = "/app/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-f8fda810b3.zip"
		babelCachePath = "/app/.yarn/cache/@babel-core-npm-7.28.0-0123456789-abcdef0123.zip"
		debug2Path     = "/app/.yarn/cache/debug-npm-2.6.9-7d4cb597dc-121908fb83.zip"
		debug4Path     = "/app/.yarn/cache/debug-npm-4.3.4-4b45b5c91c-cedbec4529.zip"
	)

	ginkgo.It("gives each npm entry of the lockfile the cache archives holding its checksum", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile(strings.TrimPrefix(babelCachePath, "/"), babelArchive),
			regularFile(strings.TrimPrefix(debug2Path, "/"), debug2Archive),
			regularFile(strings.TrimPrefix(debug4Path, "/"), debug4Archive),
			regularFile("srv/copy/ms.zip", msArchive),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:2.1.3, ms@npm:^2.1.1", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
				berryLockEntry{descriptor: "@babel/core@npm:^7.28.0", resolution: "@babel/core@npm:7.28.0", checksum: berryChecksumOf(babelArchive)},
				berryLockEntry{descriptor: "debug@npm:2.6.9", resolution: "debug@npm:2.6.9", checksum: berryChecksumOf(debug2Archive)},
				berryLockEntry{descriptor: "debug@npm:^4.3.4", resolution: "debug@npm:4.3.4", checksum: berryChecksumOf(debug4Archive)},
			)),
		})

		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.ConsistOf(
			Fileset{
				Ecosystem: EcosystemJavaScript, Name: "@babel/core", Version: "7.28.0", DeclaresFiles: true, Symlinks: map[string]string{},
				Files: map[string]File{babelCachePath: filesets.Index.Files[babelCachePath]},
			},
			Fileset{
				Ecosystem: EcosystemJavaScript, Name: "debug", Version: "2.6.9", DeclaresFiles: true, Symlinks: map[string]string{},
				Files: map[string]File{debug2Path: filesets.Index.Files[debug2Path]},
			},
			Fileset{
				Ecosystem: EcosystemJavaScript, Name: "debug", Version: "4.3.4", DeclaresFiles: true, Symlinks: map[string]string{},
				Files: map[string]File{debug4Path: filesets.Index.Files[debug4Path]},
			},
			Fileset{
				Ecosystem: EcosystemJavaScript, Name: "ms", Version: "2.1.3", DeclaresFiles: true, Symlinks: map[string]string{},
				Files: map[string]File{msCachePath: filesets.Index.Files[msCachePath], "/srv/copy/ms.zip": filesets.Index.Files["/srv/copy/ms.zip"]},
			},
		))
		gomega.Expect(filesets.Index.Files[msCachePath].Digest).To(gomega.Equal(digestOf(msArchive)))
	})

	ginkgo.It("finds an archive in the global cache, and through a hardlink", func(ctx ginkgo.SpecContext) {
		globalPath := "/root/.yarn/berry/cache/ms-npm-2.1.3-81ff3cfac1-10c0.zip"
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(globalPath, "/"), msArchive),
			hardlink("app/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-10c0.zip", strings.TrimPrefix(globalPath, "/")),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:^2.1.1", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
			)),
		})

		ms := filesetOf(filesets, EcosystemJavaScript, "ms", "2.1.3")
		gomega.Expect(ms).NotTo(gomega.BeNil())
		gomega.Expect(ms.Files).To(gomega.HaveLen(2))
		gomega.Expect(ms.Files).To(gomega.HaveKey(globalPath))
		gomega.Expect(ms.Files).To(gomega.HaveKey("/app/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-10c0.zip"))
	})

	ginkgo.It("finds an archive through a hardlink whose target is not named as one", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile("srv/objects/blob", msArchive),
			hardlink(strings.TrimPrefix(msCachePath, "/"), "srv/objects/blob"),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:^2.1.1", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
			)),
		})

		ms := filesetOf(filesets, EcosystemJavaScript, "ms", "2.1.3")
		gomega.Expect(ms).NotTo(gomega.BeNil())
		gomega.Expect(ms.Files).To(gomega.HaveKey(msCachePath))
	})

	ginkgo.It("takes the union of every lockfile naming the same package", func(ctx ginkgo.SpecContext) {
		repacked := "ms 2.1.3 archive under another cache key"
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile("other/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-8.zip", repacked),
			regularFile("app/node_modules/ms/package.json", `{"name":"ms","version":"2.1.3"}`),
			regularFile("app/node_modules/ms/index.js", "ms"),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
			)),
			regularFile("other/yarn.lock", berryLockOf("8",
				berryLockEntry{descriptor: "ms@npm:^2.1.1", resolution: "ms@npm:2.1.3", checksum: "8/" + sha512Of(repacked)},
			)),
		})

		archives := lo.Filter(javascriptFilesetsOf(filesets), func(fileset Fileset, _ int) bool { return fileset.Files[msCachePath].Digest != "" })
		gomega.Expect(archives).To(gomega.HaveLen(1))
		gomega.Expect(archives[0].Files).To(gomega.HaveLen(2))
		gomega.Expect(archives[0].Files).To(gomega.HaveKey("/other/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-8.zip"))

		bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/ms@2.1.3")}}
		gomega.Expect(RecordOccurrences(ctx, bom, filesets.Filesets)).To(gomega.Equal(1))
		gomega.Expect(lo.Map(lo.FromPtr((*bom.Components)[0].Evidence.Occurrences), func(occurrence cdx.EvidenceOccurrence, _ int) string {
			return occurrence.Location
		})).To(gomega.ConsistOf(msCachePath, "/other/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-8.zip", "/app/node_modules/ms/index.js", "/app/node_modules/ms/package.json"),
			"the archives join the node_modules copy of the same package")
	})

	ginkgo.It("accepts a checksum without the cache key Yarn 3 leaves out", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile("app/yarn.lock", berryLockOf("8",
				berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: sha512Of(msArchive)},
			)),
		})

		ms := filesetOf(filesets, EcosystemJavaScript, "ms", "2.1.3")
		gomega.Expect(ms).NotTo(gomega.BeNil())
		gomega.Expect(ms.Files).To(gomega.HaveKey(msCachePath))
	})

	ginkgo.It("gives no fileset to an entry whose checksum no archive matches", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), "tampered archive"),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
			)),
		})

		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.BeEmpty())
	})

	ginkgo.It("leaves a package whose archive the image does not hold unknown rather than absent", func(ctx ginkgo.SpecContext) {
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
			)),
		})
		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.BeEmpty())

		bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/ms@2.1.3")}}
		gomega.Expect(RecordOccurrences(ctx, bom, filesets.Filesets)).To(gomega.BeZero())
		gomega.Expect(MarkNotShipped(ctx, bom, filesets)).To(gomega.BeZero())
		gomega.Expect(isShipped((*bom.Components)[0])).To(gomega.BeTrue())
	})

	ginkgo.It("gives no fileset to an entry not resolved from the npm registry", func(ctx ginkgo.SpecContext) {
		archive := func(name string) tarEntry {
			return regularFile("app/.yarn/cache/"+name+".zip", name+" archive")
		}
		entry := func(resolution, name string) berryLockEntry {
			return berryLockEntry{descriptor: resolution, resolution: resolution, checksum: berryChecksumOf(name + " archive")}
		}

		filesets := collectFilesetsOf(ctx, []tarEntry{
			archive("patched"), archive("local"), archive("linked"), archive("portal"), archive("git"), archive("tarball"), archive("aliased"),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				entry("app@workspace:.", "app"),
				entry("patched@patch:patched@npm%3A1.0.0#~/.yarn/patches/patched.patch::version=1.0.0&hash=abc123", "patched"),
				entry("local@file:1.0.0", "local"),
				entry("linked@link:1.0.0", "linked"),
				entry("portal@portal:1.0.0", "portal"),
				entry("git@https://github.com/owner/git.git#commit=0123456789abcdef", "git"),
				entry("tarball@https://example.test/tarball-1.0.0.tgz", "tarball"),
				entry("aliased@virtual:0123456789#npm:1.0.0", "aliased"),
			)),
		})

		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.BeEmpty())
	})

	ginkgo.It("reads only Berry lockfiles", func(ctx ginkgo.SpecContext) {
		withoutMetadata := strings.Replace(berryLockOf("10c0",
			berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
		), "__metadata:\n  version: 8\n  cacheKey: 10c0\n", "", 1)
		classic := "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n" +
			"ms@^2.1.1:\n  version \"2.1.3\"\n  resolved \"https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz#574c8138ce1d2b5861f0b44579dbadd60c6615b2\"\n" +
			"  integrity sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==\n"

		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile("app/yarn.lock", withoutMetadata),
			regularFile("classic/yarn.lock", classic),
		})

		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.BeEmpty())
	})

	ginkgo.DescribeTable("bounds what it captures of a lockfile",
		func(file string, size int64, captured bool) {
			gomega.Expect(capturesFilesetFile(file, size)).To(gomega.Equal(captured))
		},
		ginkgo.Entry("a lockfile within the limit", "/app/yarn.lock", maxYarnLockBytes, true),
		ginkgo.Entry("a lockfile over the limit", "/app/yarn.lock", maxYarnLockBytes+1, false),
		ginkgo.Entry("a lockfile reached through a hardlink of unknown size", "/app/yarn.lock", int64(-1), false),
		ginkgo.Entry("another file of that size", "/app/yarn.lock.bak", int64(1024), false),
	)

	ginkgo.It("warns about a lockfile over the limit and takes nothing from it", func(ctx ginkgo.SpecContext) {
		lock := berryLockOf("10c0",
			berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
		)
		lock += strings.Repeat("#", int(maxYarnLockBytes)+1-len(lock))

		var output bytes.Buffer
		filesets := collectFilesetsOf(logboek.NewContext(ctx, logboek.NewLogger(&output, &output)), []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile("app/yarn.lock", lock),
		})

		gomega.Expect(javascriptFilesetsOf(filesets)).To(gomega.BeEmpty())
		gomega.Expect(output.String()).To(gomega.ContainSubstring("Yarn lockfile /app/yarn.lock is over"))

		bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/ms@2.1.3")}}
		RecordOccurrences(ctx, bom, filesets.Filesets)
		gomega.Expect(MarkNotShipped(ctx, bom, filesets)).To(gomega.BeZero())
	})

	ginkgo.It("does not read a lockfile body over the limit, however it was captured", func(ctx ginkgo.SpecContext) {
		lock := berryLockOf("10c0",
			berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
		)
		lock += strings.Repeat("#", int(maxYarnLockBytes)+1-len(lock))
		index := indexOf(map[string]File{
			msCachePath:      {Digest: digestOf(msArchive), Size: int64(len(msArchive)), sha512: sha512Of(msArchive)},
			"/app/yarn.lock": {Digest: digestOf(lock), Size: int64(len(lock))},
		})

		gomega.Expect(yarnPnPFilesets(ctx, index, map[string][]byte{"/app/yarn.lock": []byte(lock)}, nil)).To(gomega.BeEmpty())
	})

	ginkgo.It("does not hold a lockfile reached through a hardlink in memory, whatever its size", func(ctx ginkgo.SpecContext) {
		lock := berryLockOf("10c0",
			berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
		)
		lock += strings.Repeat("#", int(maxYarnLockBytes)+1-len(lock))
		img, err := imageOf([]tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile("srv/objects/lock", lock),
			hardlink("app/yarn.lock", "srv/objects/lock"),
		})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		index, captured, err := indexImageFiles(ctx, img, capturesFilesetFile)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(index.Files).To(gomega.HaveKey("/app/yarn.lock"))
		gomega.Expect(lo.Keys(captured)).NotTo(gomega.ContainElement("/app/yarn.lock"))
	})

	ginkgo.It("still takes an unplugged package from its node_modules tree", func(ctx ginkgo.SpecContext) {
		root := "app/.yarn/unplugged/esbuild-npm-0.20.0-0123456789/node_modules/esbuild"
		filesets := collectFilesetsOf(ctx, []tarEntry{
			regularFile(root+"/package.json", `{"name":"esbuild","version":"0.20.0"}`),
			regularFile(root+"/bin/esbuild", "esbuild binary"),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "esbuild@npm:0.20.0", resolution: "esbuild@npm:0.20.0", checksum: berryChecksumOf("esbuild archive")},
			)),
		})

		esbuild := filesetOf(filesets, EcosystemJavaScript, "esbuild", "0.20.0")
		gomega.Expect(esbuild).NotTo(gomega.BeNil())
		gomega.Expect(esbuild.Files).To(gomega.HaveKey("/" + root + "/bin/esbuild"))
	})

	ginkgo.DescribeTable("leaves a package whose archive lies inside another package's tree unknown",
		func(ctx ginkgo.SpecContext, root string) {
			fixtures := root + "/fixtures"
			filesets := collectFilesetsOf(ctx, []tarEntry{
				regularFile(root+"/package.json", `{"name":"debug","version":"4.3.4"}`),
				regularFile(root+"/index.js", "debug"),
				regularFile(fixtures+"/.yarn/cache/ms-npm-2.1.3-81ff3cfac1-f8fda810b3.zip", msArchive),
				regularFile(fixtures+"/yarn.lock", berryLockOf("10c0",
					berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
				)),
			})

			bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/debug@4.3.4"), componentOf("pkg:npm/ms@2.1.3")}}
			RecordOccurrences(ctx, bom, filesets.Filesets)
			gomega.Expect(MarkNotShipped(ctx, bom, filesets)).To(gomega.BeZero())
			gomega.Expect(isShipped((*bom.Components)[1])).To(gomega.BeTrue())
			gomega.Expect(filesetOf(filesets, EcosystemJavaScript, "ms", "2.1.3")).To(gomega.BeNil())
		},
		ginkgo.Entry("under node_modules", "app/node_modules/debug"),
		ginkgo.Entry("in a distribution directory", "usr/share/nodejs/debug"),
	)

	ginkgo.It("proves a package shipped in an image that copied only its archive, and the other not", func(ctx ginkgo.SpecContext) {
		donor := collectFilesetsOf(ctx, []tarEntry{
			regularFile(strings.TrimPrefix(msCachePath, "/"), msArchive),
			regularFile(strings.TrimPrefix(debug4Path, "/"), debug4Archive),
			regularFile("app/yarn.lock", berryLockOf("10c0",
				berryLockEntry{descriptor: "ms@npm:2.1.3", resolution: "ms@npm:2.1.3", checksum: berryChecksumOf(msArchive)},
				berryLockEntry{descriptor: "debug@npm:^4.3.4", resolution: "debug@npm:4.3.4", checksum: berryChecksumOf(debug4Archive)},
			)),
		})

		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{componentOf("pkg:npm/ms@2.1.3"), componentOf("pkg:npm/debug@4.3.4")}
		gomega.Expect(RecordOccurrences(ctx, bom, donor.Filesets)).To(gomega.Equal(2))
		gomega.Expect(MarkNotShipped(ctx, bom, donor)).To(gomega.BeZero())

		data, err := cyclonedxutil.ToJSON(bom)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		consumer := collectFilesetsOf(ctx, []tarEntry{
			regularFile("srv/vendor/ms.zip", msArchive),
		})
		gomega.Expect(MarkNotShipped(ctx, read, consumer)).To(gomega.Equal(1))

		byPURL := func(purl string) cdx.Component {
			comp, found := lo.Find(lo.FromPtr(read.Components), func(comp cdx.Component) bool { return comp.PackageURL == purl })
			gomega.Expect(found).To(gomega.BeTrue())

			return comp
		}
		gomega.Expect(isShipped(byPURL("pkg:npm/ms@2.1.3"))).To(gomega.BeTrue())
		gomega.Expect(isShipped(byPURL("pkg:npm/debug@4.3.4"))).To(gomega.BeFalse())
	})
})
