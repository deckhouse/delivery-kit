package shippedscope

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/jsobserver"
)

var _ = Describe("JavaScript bundle evidence", func() {
	logOf := func(events ...jsobserver.Event) string {
		var lines []string
		for _, event := range events {
			data, err := json.Marshal(event)
			Expect(err).NotTo(HaveOccurred())
			lines = append(lines, string(data))
		}

		return strings.Join(lines, "\n") + "\n"
	}

	eventOf := func(outputs ...jsobserver.Output) jsobserver.Event {
		return jsobserver.Event{Version: jsobserver.ProtocolVersion, Outputs: outputs}
	}

	outputOf := func(path, body string, packages ...string) jsobserver.Output {
		output := jsobserver.Output{Path: path, Digest: digestOf(body), Packages: []jsobserver.Package{}}
		for _, pkg := range packages {
			at := strings.LastIndex(pkg, "@")
			output.Packages = append(output.Packages, jsobserver.Package{Name: pkg[:at], Version: pkg[at+1:]})
		}

		return output
	}

	collect := func(ctx context.Context, entries ...tarEntry) *Filesets {
		img, err := imageOf(entries)
		Expect(err).NotTo(HaveOccurred())
		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		return filesets
	}

	bundleOf := func(path, body string, verified bool, packages ...BundlePackage) BundleOutput {
		return BundleOutput{Path: path, Digest: digestOf(body), Packages: packages, Verified: verified}
	}

	bundleOccurrence := func(path, body string) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: path, AdditionalContext: "werf:js-bundle:v1:" + digestOf(body)}
	}

	fileOccurrence := func(path, body string) cdx.EvidenceOccurrence {
		return cdx.EvidenceOccurrence{Location: path, AdditionalContext: digestOf(body)}
	}

	shipped := func(comp cdx.Component) bool {
		return !lo.Contains(lo.FromPtr(comp.Properties), cdx.Property{Name: PropertyShipped, Value: "false"})
	}

	occurrencesOf := func(comp cdx.Component) []cdx.EvidenceOccurrence {
		if comp.Evidence == nil {
			return nil
		}

		return lo.FromPtr(comp.Evidence.Occurrences)
	}

	Describe("CollectFilesets", func() {
		It("verifies each output against the bytes the image holds at its path", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/a.js", "chunk a"),
				regularFile("app/dist/b.js", "chunk b"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/a.js", "chunk a", "left-pad@1.3.0", "@scope/Lib@2.0.0-rc.1")),
					eventOf(outputOf("/app/dist/b.js", "chunk b", "right-pad@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/a.js", "chunk a", true, BundlePackage{Name: "left-pad", Version: "1.3.0"}, BundlePackage{Name: "@scope/Lib", Version: "2.0.0-rc.1"}),
				bundleOf("/app/dist/b.js", "chunk b", true, BundlePackage{Name: "right-pad", Version: "1.0.0"}),
			))
			Expect(filesets.Index.Files).NotTo(HaveKey(jsobserver.LogPath), "the log is werf's own state, not a file any component ships")
			Expect(filesets.Index.Files).To(HaveKey("/app/dist/a.js"))
		})

		It("takes the last record of an output the build wrote more than once", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/main.js", "rewritten"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/main.js", "first build", "old-dep@1.0.0")),
					eventOf(outputOf("/app/dist/main.js", "rewritten", "new-dep@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/main.js", "rewritten", true, BundlePackage{Name: "new-dep", Version: "1.0.0"}),
			), "the overridden record neither proves nor clouds the package it named")
		})

		It("leaves an output whose bytes changed after it was recorded unverified", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/main.js", "minified afterwards"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/main.js", "as bundled", "dep@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/main.js", "as bundled", false, BundlePackage{Name: "dep", Version: "1.0.0"}),
			))
		})

		It("verifies an output a later step of the same build moved, by its bytes, and names its pruned packages", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("srv/www/main.js", "as bundled"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/main.js", "as bundled", "dep@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/main.js", "as bundled", true, BundlePackage{Name: "dep", Version: "1.0.0"}),
			), "the code is in the image wherever it went; the path stays the one it was observed at")
			Expect(BundleComponents(ctx, filesets, nil)).To(Equal([]cdx.Component{
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/dep@1.0.0", Name: "dep", Version: "1.0.0", PackageURL: "pkg:npm/dep@1.0.0"},
			}))
		})

		It("keeps an overridden output whose bytes were moved before its path was written again", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/main.js", "second build"),
				regularFile("srv/www/main.js", "first build"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/main.js", "first build", "old-dep@1.0.0")),
					eventOf(outputOf("/app/dist/main.js", "second build", "new-dep@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/main.js", "first build", true, BundlePackage{Name: "old-dep", Version: "1.0.0"}),
				bundleOf("/app/dist/main.js", "second build", true, BundlePackage{Name: "new-dep", Version: "1.0.0"}),
			))
		})

		It("keeps every package named for the same bytes at the same path", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/main.js", "same bytes"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/main.js", "same bytes", "dep@1.0.0", "shared@1.0.0")),
					eventOf(outputOf("/app/dist/main.js", "same bytes", "dep@2.0.0", "shared@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/main.js", "same bytes", true,
					BundlePackage{Name: "dep", Version: "1.0.0"},
					BundlePackage{Name: "shared", Version: "1.0.0"},
					BundlePackage{Name: "dep", Version: "2.0.0"},
				),
			), "either build's copy may be the one the image ships")
			Expect(BundleComponents(ctx, filesets, nil)).To(Equal([]cdx.Component{
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/dep@1.0.0", Name: "dep", Version: "1.0.0", PackageURL: "pkg:npm/dep@1.0.0"},
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/dep@2.0.0", Name: "dep", Version: "2.0.0", PackageURL: "pkg:npm/dep@2.0.0"},
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/shared@1.0.0", Name: "shared", Version: "1.0.0", PackageURL: "pkg:npm/shared@1.0.0"},
			}))
		})

		It("takes nothing from an empty output", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/empty.js", ""),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(
					eventOf(outputOf("/app/dist/empty.js", "", "dep@1.0.0")),
				)),
			)

			Expect(filesets.Bundles).To(BeEmpty())
		})

		It("reads the valid records around malformed ones and warns", func(ctx SpecContext) {
			badDigest := outputOf("/app/dist/c.js", "chunk c", "clouded@1.0.0")
			badDigest.Digest = "sha256:ABC"
			badPath := outputOf("app/dist/../d.js", "chunk d", "relative@1.0.0")
			badPackages := outputOf("/app/dist/a.js", "chunk a", "good@1.0.0")
			badPackages.Packages = append(badPackages.Packages,
				jsobserver.Package{Name: "Bad Name", Version: "1.0.0"},
				jsobserver.Package{Name: "loose", Version: "^1.0"},
				jsobserver.Package{Name: "@scope/", Version: "1.0.0"},
				jsobserver.Package{Name: "", Version: "1.0.0"},
			)
			onlyBad := outputOf("/app/dist/e.js", "chunk e")
			onlyBad.Packages = []jsobserver.Package{{Name: "_private", Version: "1.0.0"}}
			log := "not json\n" +
				`{"version":2,"outputs":[{"path":"/app/dist/a.js","digest":"` + digestOf("chunk a") + `","packages":[{"name":"future","version":"1.0.0"}]}]}` + "\n" +
				"\n" +
				logOf(
					eventOf(badDigest, badPath, badPackages, onlyBad),
					jsobserver.Event{Version: jsobserver.ProtocolVersion, Warning: "unsupported Node runtime"},
				) +
				`{"version":1,"outputs":[{"path":"/app/dist/b.js","digest":"` + digestOf("chunk b")

			var output bytes.Buffer
			filesets := collect(logboek.NewContext(ctx, logboek.NewLogger(&output, &output)),
				regularFile("app/dist/a.js", "chunk a"),
				regularFile("app/dist/b.js", "chunk b"),
				regularFile("app/dist/c.js", "chunk c"),
				regularFile("app/dist/e.js", "chunk e"),
				regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), log),
			)
			out := output.String()

			Expect(filesets.Bundles).To(ConsistOf(
				bundleOf("/app/dist/a.js", "chunk a", true, BundlePackage{Name: "good", Version: "1.0.0"}),
				BundleOutput{Path: "/app/dist/c.js", Digest: "sha256:ABC", Packages: []BundlePackage{{Name: "clouded", Version: "1.0.0"}}},
				BundleOutput{Path: "app/dist/../d.js", Digest: digestOf("chunk d"), Packages: []BundlePackage{{Name: "relative", Version: "1.0.0"}}},
			), "an unreadable output still clouds the packages it names; an unreadable package proves nothing")
			Expect(out).To(ContainSubstring("unsupported Node runtime"))
			Expect(out).To(ContainSubstring("JavaScript bundle observer"))
		})

		DescribeTable("bounds what it captures of the log",
			func(file string, size int64, captured bool) {
				Expect(capturesFilesetFile(file, size)).To(Equal(captured))
			},
			Entry("a log within the limit", jsobserver.LogPath, int64(1024), true),
			Entry("a log over the limit", jsobserver.LogPath, maxJSObserverLogBytes+1, false),
			Entry("a log reached through a hardlink of unknown size", jsobserver.LogPath, int64(-1), false),
			Entry("a manifest of any size", "/app/node_modules/dep/package.json", maxJSObserverLogBytes+1, true),
		)

		It("takes nothing from a log that is a symlink", func(ctx SpecContext) {
			filesets := collect(ctx,
				regularFile("app/dist/main.js", "chunk"),
				regularFile("srv/log.jsonl", logOf(eventOf(outputOf("/app/dist/main.js", "chunk", "dep@1.0.0")))),
				symlink(strings.TrimPrefix(jsobserver.LogPath, "/"), "/srv/log.jsonl"),
			)

			Expect(filesets.Bundles).To(BeEmpty())
		})

		It("takes nothing when the build left no log", func(ctx SpecContext) {
			filesets := collect(ctx, regularFile("app/dist/main.js", "chunk"))

			Expect(filesets.Bundles).To(BeNil())
		})
	})

	Describe("BundleComponents", func() {
		It("names the verified packages no BOM holds, as minimal npm components", func(ctx SpecContext) {
			filesets := &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/a.js", "a", true, BundlePackage{Name: "listed", Version: "1.0.0"}, BundlePackage{Name: "@Scope/Pruned", Version: "2.0.0"}),
				bundleOf("/app/dist/b.js", "b", true, BundlePackage{Name: "pruned", Version: "3.0.0"}, BundlePackage{Name: "@Scope/Pruned", Version: "2.0.0"}),
				bundleOf("/app/dist/c.js", "c", false, BundlePackage{Name: "unverified", Version: "1.0.0"}),
				bundleOf("/app/dist/d.js", "d", true, BundlePackage{Name: "@scope/installed", Version: "1.0.0+build.1"}),
			}}
			listed := &cdx.BOM{Components: &[]cdx.Component{
				{Name: "Listed", Version: "1.0.0", PackageURL: "pkg:npm/Listed@1.0.0", Licenses: &cdx.Licenses{{License: &cdx.License{ID: "MIT"}}}},
				{Name: "@scope/installed", Version: "1.0.0+build.1", PackageURL: "pkg:npm/%40scope/installed@1.0.0%2Bbuild.1"},
			}}

			components := BundleComponents(ctx, filesets, []*cdx.BOM{nil, listed})

			Expect(components).To(Equal([]cdx.Component{
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/%40scope/pruned@2.0.0", Name: "@Scope/Pruned", Version: "2.0.0", PackageURL: "pkg:npm/%40scope/pruned@2.0.0"},
				{Type: cdx.ComponentTypeLibrary, BOMRef: "pkg:npm/pruned@3.0.0", Name: "pruned", Version: "3.0.0", PackageURL: "pkg:npm/pruned@3.0.0"},
			}))
			Expect(lo.FromPtr(listed.Components)[0].Licenses).NotTo(BeNil(), "an existing component is not touched")
		})

		It("names nothing without verified outputs", func(ctx SpecContext) {
			Expect(BundleComponents(ctx, &Filesets{}, nil)).To(BeEmpty())
			Expect(BundleComponents(ctx, nil, nil)).To(BeEmpty())
		})
	})

	Describe("RecordBundleOccurrences", func() {
		It("credits disjoint chunks to their own packages and a shared chunk to every version it holds", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/first@1.0.0"),
				componentOf("pkg:npm/second@1.0.0"),
				componentOf("pkg:npm/%40scope/shared@1.0.0"),
				componentOf("pkg:npm/%40scope/shared@2.0.0"),
				componentOf("pkg:npm/unrelated@1.0.0"),
				componentOf("pkg:pypi/first@1.0.0"),
			}}

			recorded := RecordBundleOccurrences(ctx, bom, &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/first.js", "first chunk", true, BundlePackage{Name: "first", Version: "1.0.0"}),
				bundleOf("/app/dist/second.js", "second chunk", true, BundlePackage{Name: "second", Version: "1.0.0"}),
				bundleOf("/app/dist/vendor.js", "vendor chunk", true,
					BundlePackage{Name: "@scope/shared", Version: "1.0.0"},
					BundlePackage{Name: "@Scope/Shared", Version: "2.0.0"},
					BundlePackage{Name: "first", Version: "1.0.0"},
				),
			}})

			Expect(recorded).To(Equal(4))
			components := *bom.Components
			Expect(occurrencesOf(components[0])).To(Equal([]cdx.EvidenceOccurrence{
				bundleOccurrence("/app/dist/first.js", "first chunk"),
				bundleOccurrence("/app/dist/vendor.js", "vendor chunk"),
			}))
			Expect(occurrencesOf(components[1])).To(Equal([]cdx.EvidenceOccurrence{bundleOccurrence("/app/dist/second.js", "second chunk")}))
			Expect(occurrencesOf(components[2])).To(Equal([]cdx.EvidenceOccurrence{bundleOccurrence("/app/dist/vendor.js", "vendor chunk")}))
			Expect(occurrencesOf(components[3])).To(Equal([]cdx.EvidenceOccurrence{bundleOccurrence("/app/dist/vendor.js", "vendor chunk")}))
			Expect(occurrencesOf(components[4])).To(BeNil())
			Expect(occurrencesOf(components[5])).To(BeNil(), "a package of another ecosystem with the same name is another package")
			for _, comp := range components {
				Expect(lo.FromPtr(comp.Properties)).To(BeEmpty())
			}
		})

		It("keeps what an earlier image recorded at an output this image wrote again, since those bytes may have moved", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/dep@1.0.0",
					fileOccurrence("/app/node_modules/dep/index.js", "dep"),
					bundleOccurrence("/app/dist/main.js", "donor bytes"),
					bundleOccurrence("/donor/dist/other.js", "other bytes"),
				),
			}}

			RecordBundleOccurrences(ctx, bom, &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/main.js", "this image's bytes", true, BundlePackage{Name: "dep", Version: "1.0.0"}),
			}})

			Expect(occurrencesOf((*bom.Components)[0])).To(ConsistOf(
				fileOccurrence("/app/node_modules/dep/index.js", "dep"),
				bundleOccurrence("/app/dist/main.js", "donor bytes"),
				bundleOccurrence("/app/dist/main.js", "this image's bytes"),
				bundleOccurrence("/donor/dist/other.js", "other bytes"),
			))
		})

		It("marks the packages of an unverified output unknown, and only those", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/clouded@1.0.0"),
				componentOf("pkg:npm/clear@1.0.0"),
			}}

			RecordBundleOccurrences(ctx, bom, &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/main.js", "as bundled", false, BundlePackage{Name: "clouded", Version: "1.0.0"}),
				bundleOf("/app/dist/other.js", "other", true, BundlePackage{Name: "clear", Version: "1.0.0"}),
			}})

			Expect(lo.FromPtr((*bom.Components)[0].Properties)).To(Equal([]cdx.Property{{Name: PropertyJSBundles, Value: "unknown"}}))
			Expect(occurrencesOf((*bom.Components)[0])).To(BeNil())
			Expect(lo.FromPtr((*bom.Components)[1].Properties)).To(BeEmpty(), "no checked-empty marker is invented")
		})

		DescribeTable("marks every npm package of a pruned image unknown only when the log is there but not read",
			func(ctx SpecContext, log []tarEntry, unknown bool) {
				filesets := collect(ctx, append([]tarEntry{
					regularFile("app/dist/main.js", "chunk"),
					regularFile("srv/log.jsonl", logOf(eventOf(outputOf("/app/dist/main.js", "chunk", "dep@1.0.0")))),
				}, log...)...)
				bom := &cdx.BOM{Components: &[]cdx.Component{
					componentOf("pkg:npm/other@1.0.0", fileOccurrence("/app/node_modules/other/index.js", "other")),
					componentOf("pkg:pypi/other@1.0.0", fileOccurrence("/app/lib/other.py", "other")),
				}}

				RecordBundleOccurrences(ctx, bom, filesets)
				MarkNotShipped(ctx, bom, filesets)

				npm, pypi := (*bom.Components)[0], (*bom.Components)[1]
				Expect(lo.Contains(lo.FromPtr(npm.Properties), cdx.Property{Name: PropertyJSBundles, Value: "unknown"})).To(Equal(unknown))
				Expect(shipped(npm)).To(Equal(unknown), "a log werf chose not to read cannot show a bundled package absent")
				Expect(lo.FromPtr(pypi.Properties)).NotTo(ContainElement(HaveField("Name", PropertyJSBundles)))
				Expect(shipped(pypi)).To(BeFalse())
			},
			Entry("a log that is a hardlink", []tarEntry{hardlink(strings.TrimPrefix(jsobserver.LogPath, "/"), "srv/log.jsonl")}, true),
			Entry("a log that is a symlink", []tarEntry{symlink(strings.TrimPrefix(jsobserver.LogPath, "/"), "/srv/log.jsonl")}, true),
			Entry("a log that was read", []tarEntry{regularFile(strings.TrimPrefix(jsobserver.LogPath, "/"), logOf(eventOf(outputOf("/app/dist/main.js", "chunk", "dep@1.0.0"))))}, false),
			Entry("no log", nil, false),
		)

		It("marks every npm package unknown when the log is a hardlink no layer can resolve", func(ctx SpecContext) {
			img, err := imageOf(
				[]tarEntry{
					regularFile("app/dist/main.js", "chunk"),
					regularFile("srv/log.jsonl", logOf(eventOf(outputOf("/app/dist/main.js", "chunk", "dep@1.0.0")))),
				},
				[]tarEntry{hardlink(strings.TrimPrefix(jsobserver.LogPath, "/"), "srv/log.jsonl")},
				[]tarEntry{whiteout("srv/.wh.log.jsonl")},
			)
			Expect(err).NotTo(HaveOccurred())
			filesets, err := CollectFilesets(ctx, img)
			Expect(err).NotTo(HaveOccurred())
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/other@1.0.0", fileOccurrence("/app/node_modules/other/index.js", "other")),
			}}

			RecordBundleOccurrences(ctx, bom, filesets)
			MarkNotShipped(ctx, bom, filesets)

			Expect(filesets.BundlesUnknown).To(BeTrue())
			Expect(filesets.Index.Files).NotTo(HaveKey(jsobserver.LogPath))
			Expect(filesets.Index.Symlinks).NotTo(HaveKey(jsobserver.LogPath))
			npm := (*bom.Components)[0]
			Expect(lo.FromPtr(npm.Properties)).To(ContainElement(cdx.Property{Name: PropertyJSBundles, Value: "unknown"}))
			Expect(shipped(npm)).To(BeTrue(), "a log whose content cannot be named could still name the package")
		})

		It("survives file evidence recorded over the same component", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/dep@1.0.0")}}
			RecordBundleOccurrences(ctx, bom, &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/main.js", "chunk", true, BundlePackage{Name: "dep", Version: "1.0.0"}),
			}})

			Expect(RecordOccurrences(bom, []Fileset{{
				Ecosystem: EcosystemJavaScript, Name: "dep", Version: "1.0.0", DeclaresFiles: true,
				Files: map[string]File{"/app/node_modules/dep/index.js": {Digest: digestOf("dep"), Size: 3}},
			}})).To(Equal(1))

			comp := (*bom.Components)[0]
			Expect(occurrencesOf(comp)).To(ConsistOf(
				fileOccurrence("/app/node_modules/dep/index.js", "dep"),
				bundleOccurrence("/app/dist/main.js", "chunk"),
			))
			Expect(recordedOccurrences(&comp)).To(Equal([]Occurrence{{Path: "/app/node_modules/dep/index.js", Digest: digestOf("dep")}}),
				"bundle evidence is not a file of the package")
		})

		It("keeps a checked-empty file list beside bundle evidence", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{componentOf("pkg:npm/dep@1.0.0", bundleOccurrence("/app/dist/main.js", "chunk"))}}

			Expect(RecordOccurrences(bom, []Fileset{{Ecosystem: EcosystemJavaScript, Name: "dep", Version: "1.0.0", DeclaresFiles: true}})).To(Equal(1))

			comp := (*bom.Components)[0]
			Expect(occurrencesOf(comp)).To(Equal([]cdx.EvidenceOccurrence{bundleOccurrence("/app/dist/main.js", "chunk")}))
			Expect(lo.FromPtr(comp.Properties)).To(ContainElement(cdx.Property{Name: PropertyFiles, Value: "none"}))
			Expect(recordedOccurrences(&comp)).To(Equal([]Occurrence{}))
		})
	})

	Describe("MarkNotShipped", func() {
		index := func(files map[string]string) *Filesets {
			entries := make(map[string]File, len(files))
			for file, body := range files {
				entries[file] = File{Digest: digestOf(body), Size: int64(len(body))}
			}

			return &Filesets{Index: indexOf(entries)}
		}

		It("keeps a package only a bundle in the image still holds", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/bundled@1.0.0", fileOccurrence("/app/node_modules/bundled/index.js", "bundled"), bundleOccurrence("/app/dist/main.js", "chunk")),
				componentOf("pkg:npm/shaken@1.0.0", fileOccurrence("/app/node_modules/shaken/index.js", "shaken")),
			}}

			Expect(MarkNotShipped(ctx, bom, index(map[string]string{"/app/dist/main.js": "chunk"}))).To(Equal(1))

			Expect(shipped((*bom.Components)[0])).To(BeTrue())
			Expect(shipped((*bom.Components)[1])).To(BeFalse(), "with no event and no files, the old rule still decides")
		})

		It("leaves a package without an event to its files", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/shaken@1.0.0", fileOccurrence("/app/node_modules/shaken/index.js", "shaken")),
			}}

			Expect(MarkNotShipped(ctx, bom, index(map[string]string{
				"/app/node_modules/shaken/index.js": "shaken",
				"/app/dist/main.js":                 "chunk",
			}))).To(BeZero(), "a bundle leaving a package out does not make its installed files absent")
		})

		It("finds a bundle an import moved, by its bytes", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/bundled@1.0.0", fileOccurrence("/app/node_modules/bundled/index.js", "bundled"), bundleOccurrence("/app/dist/main.js", "chunk")),
			}}

			Expect(MarkNotShipped(ctx, bom, index(map[string]string{"/srv/www/main.js": "chunk"}))).To(BeZero())
		})

		DescribeTable("does not hold a package by what is not its bundle",
			func(ctx SpecContext, files map[string]File) {
				bom := &cdx.BOM{Components: &[]cdx.Component{
					componentOf("pkg:npm/bundled@1.0.0", fileOccurrence("/app/node_modules/bundled/index.js", "bundled"), bundleOccurrence("/app/dist/main.js", "chunk")),
				}}

				Expect(MarkNotShipped(ctx, bom, &Filesets{Index: indexOf(files)})).To(Equal(1))
			},
			Entry("another file under the bundle's path", map[string]File{"/app/dist/main.js": {Digest: digestOf("rebuilt"), Size: 7}}),
			Entry("an empty file of the recorded digest", map[string]File{"/app/dist/main.js": {Digest: digestOf("chunk"), Size: 0}}),
		)

		It("proves nothing by an empty bundle", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/bundled@1.0.0", fileOccurrence("/app/node_modules/bundled/index.js", "bundled"), bundleOccurrence("/app/dist/empty.js", "")),
			}}

			Expect(MarkNotShipped(ctx, bom, index(map[string]string{"/app/dist/empty.js": ""}))).To(Equal(1))
		})

		DescribeTable("keeps a package whose bundles cannot be shown absent",
			func(ctx SpecContext, comp cdx.Component) {
				bom := &cdx.BOM{Components: &[]cdx.Component{comp}}

				Expect(MarkNotShipped(ctx, bom, index(map[string]string{"/app/dist/main.js": "other"}))).To(BeZero())
			},
			Entry("an output changed after it was observed", cdx.Component{
				PackageURL: "pkg:npm/clouded@1.0.0",
				Properties: &[]cdx.Property{{Name: PropertyJSBundles, Value: "unknown"}},
				Evidence:   &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{fileOccurrence("/app/node_modules/clouded/index.js", "clouded")}},
			}),
			Entry("a bundle record werf cannot read", cdx.Component{
				PackageURL: "pkg:npm/clouded@1.0.0",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					fileOccurrence("/app/node_modules/clouded/index.js", "clouded"),
					{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v1:sha256:XYZ"},
				}},
			}),
			Entry("a bundle record of a later format", cdx.Component{
				PackageURL: "pkg:npm/clouded@1.0.0",
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
					fileOccurrence("/app/node_modules/clouded/index.js", "clouded"),
					{Location: "/app/dist/main.js", AdditionalContext: "werf:js-bundle:v2:" + digestOf("other")},
				}},
			}),
		)

		DescribeTable("does not take a bundle occurrence it cannot read for one whose bytes are gone",
			func(ctx SpecContext, context string) {
				bom := &cdx.BOM{Components: &[]cdx.Component{
					componentOf("pkg:npm/clouded@1.0.0",
						fileOccurrence("/app/node_modules/clouded/index.js", "clouded"),
						cdx.EvidenceOccurrence{Location: "/app/dist/main.js", AdditionalContext: context},
					),
				}}

				Expect(MarkNotShipped(ctx, bom, index(map[string]string{}))).To(BeZero())
				Expect(shipped((*bom.Components)[0])).To(BeTrue())
			},
			Entry("empty digest", "werf:js-bundle:v1:"),
			Entry("future format", "werf:js-bundle:v2:"+digestOf("chunk")),
		)

		It("clears an inherited verdict once a bundle proves the package", func(ctx SpecContext) {
			bom := &cdx.BOM{Components: &[]cdx.Component{
				componentOf("pkg:npm/bundled@1.0.0", fileOccurrence("/app/node_modules/bundled/index.js", "bundled"), bundleOccurrence("/app/dist/main.js", "chunk")),
			}}
			setProperty(&(*bom.Components)[0], PropertyShipped, "false")

			Expect(MarkNotShipped(ctx, bom, index(map[string]string{"/app/dist/main.js": "chunk"}))).To(BeZero())
			Expect(shipped((*bom.Components)[0])).To(BeTrue())
		})

		It("reads bundle evidence back after serialization and a merge of several donors", func(ctx SpecContext) {
			donorOf := func(path, body string) *cdx.BOM {
				bom := cyclonedxutil.NewBOM()
				bom.Components = &[]cdx.Component{componentOf("pkg:npm/dep@1.0.0", fileOccurrence("/app/node_modules/dep/index.js", "dep"))}
				RecordBundleOccurrences(ctx, bom, &Filesets{Bundles: []BundleOutput{
					bundleOf(path, body, true, BundlePackage{Name: "dep", Version: "1.0.0"}),
				}})

				return bom
			}
			unknown := cyclonedxutil.NewBOM()
			unknown.Components = &[]cdx.Component{componentOf("pkg:npm/clouded@1.0.0", fileOccurrence("/app/node_modules/clouded/index.js", "clouded"))}
			RecordBundleOccurrences(ctx, unknown, &Filesets{Bundles: []BundleOutput{
				bundleOf("/app/dist/main.js", "chunk", false, BundlePackage{Name: "clouded", Version: "1.0.0"}),
			}})

			target := cyclonedxutil.NewBOM()
			merged, err := cyclonedxutil.MergeBOMs(ctx, target, cyclonedxutil.MergeOpts{ImportBOMs: []*cdx.BOM{
				donorOf("/first/main.js", "first chunk"), donorOf("/second/main.js", "second chunk"), unknown,
			}})
			Expect(err).NotTo(HaveOccurred())
			data, err := cyclonedxutil.ToJSON(merged)
			Expect(err).NotTo(HaveOccurred())
			Expect(cyclonedxutil.ValidateCycloneDX16Schema(data)).To(Succeed())
			read, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
			Expect(err).NotTo(HaveOccurred())

			byPURL := func(bom *cdx.BOM, purl string) cdx.Component {
				comp, found := lo.Find(lo.FromPtr(bom.Components), func(comp cdx.Component) bool { return comp.PackageURL == purl })
				Expect(found).To(BeTrue())

				return comp
			}
			Expect(occurrencesOf(byPURL(read, "pkg:npm/dep@1.0.0"))).To(ContainElements(
				bundleOccurrence("/first/main.js", "first chunk"),
				bundleOccurrence("/second/main.js", "second chunk"),
			))

			Expect(MarkNotShipped(ctx, read, index(map[string]string{"/srv/second.js": "second chunk"}))).To(BeZero(),
				"the second donor's chunk holds the package, and the clouded one stays unknown")
			Expect(lo.FromPtr(byPURL(read, "pkg:npm/clouded@1.0.0").Properties)).To(ContainElement(cdx.Property{Name: PropertyJSBundles, Value: "unknown"}))

			Expect(MarkNotShipped(ctx, read, index(map[string]string{}))).To(Equal(1), "without any of its chunks or files the package is not shipped")
			Expect(shipped(byPURL(read, "pkg:npm/dep@1.0.0"))).To(BeFalse())
		})
	})

	Describe("Match", func() {
		It("holds a package by any bundle in the image, however many packages it holds", func(ctx SpecContext) {
			bundles := []Occurrence{{Path: "/app/dist/vendor.js", Digest: digestOf("vendor")}}
			components := []Component{
				{Ecosystem: EcosystemJavaScript, Name: "a", Version: "1.0.0", Occurrences: []Occurrence{}, Bundles: bundles},
				{Ecosystem: EcosystemJavaScript, Name: "a", Version: "2.0.0", Occurrences: []Occurrence{}, Bundles: bundles},
				{Ecosystem: EcosystemJavaScript, Name: "b", Version: "1.0.0", Occurrences: []Occurrence{}},
			}

			decisions := Match(ctx, components, ProducedBinaries{}, indexOf(map[string]File{
				"/srv/vendor.js": {Digest: digestOf("vendor"), Size: 6},
			}))

			Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonBundle, Matched: []string{"/srv/vendor.js"}}))
			Expect(decisions[1]).To(Equal(Decision{Shipped: true, Reason: ReasonBundle, Matched: []string{"/srv/vendor.js"}}))
			Expect(decisions[2].Shipped).To(BeFalse())
		})

		It("says why a package with no file evidence is kept", func(ctx SpecContext) {
			components := []Component{
				{Ecosystem: EcosystemJavaScript, Name: "bundled", Version: "1.0.0", Bundles: []Occurrence{{Path: "/app/dist/main.js", Digest: digestOf("main")}}},
				{Ecosystem: EcosystemJavaScript, Name: "missing", Version: "1.0.0", Bundles: []Occurrence{{Path: "/app/dist/gone.js", Digest: digestOf("gone")}}},
			}

			decisions := Match(ctx, components, ProducedBinaries{}, indexOf(map[string]File{
				"/srv/main.js": {Digest: digestOf("main"), Size: 4},
			}))

			Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonBundle, Matched: []string{"/srv/main.js"}}))
			Expect(decisions[1]).To(Equal(Decision{Shipped: true, Reason: ReasonNoData}),
				"without file evidence its code may still ship untracked, so a missing bundle is not absence")
		})
	})
})
