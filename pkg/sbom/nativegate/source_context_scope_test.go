package nativegate

import (
	"encoding/json"
	"maps"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/buildcontext"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/original"
	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// declaredContextSource is one prepared source: the receipt entry the actual source image
// carries, and the original the caller resolved and verified before the context is built.
func declaredContextSource(repo, pkg string, files map[string]string) (sources.Source, *resolvedSource) {
	ginkgo.GinkgoHelper()
	image := fixtureImage(files)
	pinned, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	payload, err := original.NewOriginalPackage(image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(payload.Complete()).To(gomega.BeTrue())

	source := sources.Source{Registry: repo, Platform: "linux/amd64", Packet: json.RawMessage(transportPacket(pkg, pinned.String(), "plain"))}
	metadata, err := readSourcePackage(source)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	platform, err := v1.ParsePlatform(source.Platform)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	pin, err := original.PinnedDigest(metadata.Name, metadata.Version, metadata.Arch, metadata.Digest, *platform)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return source, &resolvedSource{ID: originalSourceID(repo, pin, *platform), Source: source, Package: metadata, Original: payload}
}

func contextPackages(resolved ...*resolvedSource) (map[string]*resolvedSource, map[string]int) {
	packages := make(map[string]*resolvedSource, len(resolved))
	indexes := make(map[string]int, len(resolved))
	for position, source := range resolved {
		packages[source.ID] = source
		indexes[source.ID] = position
	}

	return packages, indexes
}

func contextPackageIndex(position int) *int { return &position }

var _ = ginkgo.Describe("producer context import scope", func() {
	ginkgo.It("maps a declared original onto the destination the import scope actually carried", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body", "/src/two.c": "two body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body", "/work/two.c": "two body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body", "/src/two.c": "two body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work", IncludePaths: []string{"one.c"}},
				}},
			},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/work/one.c", Package: contextPackageIndex(0), OriginalPath: "src/one.c"},
		}))
	})

	ginkgo.It("follows an imported original to where a later shell stage moved it", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
			{Stage: "install", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/usr/src/one.c": "one body"})},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/usr/src/one.c", Package: contextPackageIndex(0), OriginalPath: "src/one.c"},
		}))
	})

	ginkgo.It("leaves equal bytes the build already held outside the import unmapped", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/vendor/one.c": "one body"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/vendor/one.c": "one body", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/work/one.c", Package: contextPackageIndex(0), OriginalPath: "src/one.c"},
		}))
	})

	ginkgo.It("refuses the whole context when two declared sources could be the one origin", func(ctx ginkgo.SpecContext) {
		first, firstResolved := declaredContextSource("registry.example.com/sources/first", "first-source", map[string]string{"/src/one.c": "one body"})
		second, secondResolved := declaredContextSource("registry.example.com/sources/second", "second-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(firstResolved, secondResolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{
					{
						Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
						Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{first}},
						Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
					},
					{
						Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
						Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{second}},
						Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
					},
				},
			},
		}

		_, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: 2 original bindings")))
	})

	ginkgo.It("binds nothing from a source image entry the context does not declare", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		other, _ := declaredContextSource("registry.example.com/sources/other", "other-source", map[string]string{"/src/extra.c": "extra body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body", "/work/extra.c": "extra body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body", "/src/extra.c": "extra body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source, other}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/work/one.c", Package: contextPackageIndex(0), OriginalPath: "src/one.c"},
		}))
	})

	ginkgo.It("refuses a second spelling of a declared source instead of taking the first", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		rewritten := source
		rewritten.Packet = json.RawMessage(transportPacket("tool-source", resolved.Package.Digest, "rewritten"))
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{rewritten}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		_, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: original source pm-source:")))
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("conflicting Packet metadata")))
	})

	ginkgo.It("refuses a source import that carries no receipt", func(ctx ginkgo.SpecContext) {
		_, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index: fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Scope: ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		_, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: the imported source image carries no original source receipt")))
	})

	ginkgo.It("refuses a receipt entry whose identity it cannot pin", func(ctx ginkgo.SpecContext) {
		_, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		broken := sources.Source{Registry: "registry.example.com/sources/tool", Platform: "linux/amd64", Packet: json.RawMessage(transportPacket("tool-source", "sha256:not-a-digest", "plain"))}
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{broken}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		_, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid pinned package digest")))
	})

	ginkgo.It("refuses an incomplete stage snapshot", func(ctx ginkgo.SpecContext) {
		_, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		incomplete := fixtureIndex(map[string]string{"/bin/sh": "shell"})
		incomplete.Incomplete = true

		_, err := producerContextImports(ctx, []SourceSnapshot{{Stage: "from", Index: incomplete}}, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: incomplete source snapshot for from")))

		_, err = producerContextImports(ctx, nil, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: the producer context needs the actual stage snapshots")))
	})

	ginkgo.It("refuses an import on the base snapshot, which precedes no stage", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{{
			Stage: "from",
			Index: fixtureIndex(map[string]string{"/work/one.c": "one body"}),
			Imports: []SourceImport{{
				Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
				Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
				Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
			}},
		}}

		_, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: the base snapshot from precedes no stage")))
	})

	ginkgo.It("maps nothing when no stage imported a declared source", func(ctx ginkgo.SpecContext) {
		_, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{Stage: "install", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"})},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).NotTo(gomega.BeNil())
		gomega.Expect(imports).To(gomega.BeEmpty())
	})

	ginkgo.It("refuses a binding the context packages do not hold a place for", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, _ := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
		}

		_, err := producerContextImports(ctx, snapshots, packages, map[string]int{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: no context package for original source")))
	})
})

var _ = ginkgo.Describe("producer context over files that share their bytes with an original", func() {
	// The shape a real strict builder arrived in: a stock base holding an empty
	// /.dockerenv, and a prepared source whose packet carries several empty files of its
	// own. Nothing moved /.dockerenv anywhere - it stood where it always stood - but its
	// bytes are every empty file's bytes, and it was being handed every one of their
	// bindings at once.
	ginkgo.It("says nothing of a file the stage left untouched, whatever it is byte for byte", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/golang", "golang-source", map[string]string{
			"/src/go.mod":              "module example",
			"/src/testdata/empty_a.go": "",
			"/src/testdata/empty_b.go": "",
			"/src/testdata/empty_c.go": "",
		})
		packages, indexes := contextPackages(resolved)
		base := map[string]string{"/bin/sh": "shell", "/.dockerenv": ""}
		installed := map[string]string{
			"/bin/sh": "shell", "/.dockerenv": "",
			"/usr/local/go/go.mod":              "module example",
			"/usr/local/go/testdata/empty_a.go": "",
			"/usr/local/go/testdata/empty_b.go": "",
			"/usr/local/go/testdata/empty_c.go": "",
		}
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(base)},
			{
				Stage: "dependencies",
				Index: fixtureIndex(installed),
				Imports: []SourceImport{{
					Index: fixtureIndex(map[string]string{
						"/src/go.mod":              "module example",
						"/src/testdata/empty_a.go": "",
						"/src/testdata/empty_b.go": "",
						"/src/testdata/empty_c.go": "",
					}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/usr/local/go"},
				}},
			},
			{Stage: "install", Index: fixtureIndex(installed)},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		paths := make([]string, 0, len(imports))
		for _, imported := range imports {
			paths = append(paths, imported.Path)
		}
		gomega.Expect(paths).NotTo(gomega.ContainElement("/.dockerenv"),
			"the base's own file was never imported, and the context says nothing of it")
		gomega.Expect(imports).To(gomega.ContainElement(
			buildcontext.Import{Path: "/usr/local/go/go.mod", Package: contextPackageIndex(0), OriginalPath: "src/go.mod"},
		))
		// Each empty file of the packet is bound where it was imported to, and nowhere
		// else: the import carried it there, and nothing else is in question.
		for _, name := range []string{"empty_a.go", "empty_b.go", "empty_c.go"} {
			gomega.Expect(imports).To(gomega.ContainElement(
				buildcontext.Import{
					Path:    "/usr/local/go/testdata/" + name,
					Package: contextPackageIndex(0), OriginalPath: "src/testdata/" + name,
				}), name)
		}
	})

	// An empty file the build itself writes is new, so the rule above lets its bytes
	// speak - and they say nothing: every empty file has the same bytes, and the
	// packet's three are no more its origin than any other. Zero size is zero evidence.
	ginkgo.It("binds nothing to an empty file the stage itself created", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{
			"/src/one.c":             "one body",
			"/src/testdata/a.golden": "",
			"/src/testdata/b.golden": "",
			"/src/testdata/c.golden": "",
		})
		packages, indexes := contextPackages(resolved)
		imported := map[string]string{
			"/src/one.c": "one body", "/src/testdata/a.golden": "", "/src/testdata/b.golden": "", "/src/testdata/c.golden": "",
		}
		dependencies := map[string]string{"/bin/sh": "shell"}
		for path, body := range imported {
			dependencies[strings.Replace(path, "/src", "/work", 1)] = body
		}
		installed := maps.Clone(dependencies)
		installed["/work/.build-stamp"] = ""
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(dependencies),
				Imports: []SourceImport{{
					Index:   fixtureIndex(imported),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
			{Stage: "install", Index: fixtureIndex(installed)},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bound := make([]string, 0, len(imports))
		for _, imported := range imports {
			bound = append(bound, imported.Path)
		}
		gomega.Expect(bound).NotTo(gomega.ContainElement("/work/.build-stamp"))
		gomega.Expect(bound).To(gomega.ContainElement("/work/one.c"))
	})

	// The other half of the same rule: content a stage actually wrote still follows its
	// bytes to where it went.
	ginkgo.It("still follows content a stage moved to another path", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/.dockerenv": ""})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/.dockerenv": "", "/work/one.c": "one body"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/one.c": "one body"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
			{Stage: "install", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/.dockerenv": "", "/usr/src/one.c": "one body"})},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/usr/src/one.c", Package: contextPackageIndex(0), OriginalPath: "src/one.c"},
		}))
	})

	// Changed counts as much as new: a stage that wrote an original's bytes over a file
	// the base already held has put that content there, and the context must say so.
	ginkgo.It("follows content a stage wrote over a file the base already held", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/version.h": "#define V 2\n"})
		packages, indexes := contextPackages(resolved)
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/usr/include/version.h": "#define V 1\n"})},
			{
				Stage: "dependencies",
				Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/usr/include/version.h": "#define V 1\n", "/work/version.h": "#define V 2\n"}),
				Imports: []SourceImport{{
					Index:   fixtureIndex(map[string]string{"/src/version.h": "#define V 2\n"}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
			// The install stage overwrites the base's header with the imported one.
			{Stage: "install", Index: fixtureIndex(map[string]string{"/bin/sh": "shell", "/usr/include/version.h": "#define V 2\n"})},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(imports).To(gomega.Equal([]buildcontext.Import{
			{Path: "/usr/include/version.h", Package: contextPackageIndex(0), OriginalPath: "src/version.h"},
		}))
	})

	// The files a container runtime writes into every image - and any other file of the
	// base the build never touched - are told apart by what happened to them, not by
	// their names: nothing wrote them here, so nothing here can say they came from
	// anywhere. A list of such names would have to be kept in step with every runtime
	// there is.
	ginkgo.It("binds no file of the base that merely reads like one the import carried", func(ctx ginkgo.SpecContext) {
		source, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{
			"/src/marker":      "",
			"/src/hostname":    "builder\n",
			"/src/hosts":       "127.0.0.1 localhost\n",
			"/src/resolv.conf": "nameserver 1.1.1.1\n",
		})
		packages, indexes := contextPackages(resolved)
		runtime := map[string]string{
			"/bin/sh":          "shell",
			"/.dockerenv":      "",
			"/etc/hostname":    "builder\n",
			"/etc/hosts":       "127.0.0.1 localhost\n",
			"/etc/resolv.conf": "nameserver 1.1.1.1\n",
		}
		installed := map[string]string{
			"/work/marker": "", "/work/hostname": "builder\n",
			"/work/hosts": "127.0.0.1 localhost\n", "/work/resolv.conf": "nameserver 1.1.1.1\n",
		}
		for path, body := range runtime {
			installed[path] = body
		}
		snapshots := []SourceSnapshot{
			{Stage: "from", Index: fixtureIndex(runtime)},
			{
				Stage: "dependencies",
				Index: fixtureIndex(installed),
				Imports: []SourceImport{{
					Index: fixtureIndex(map[string]string{
						"/src/marker": "", "/src/hostname": "builder\n",
						"/src/hosts": "127.0.0.1 localhost\n", "/src/resolv.conf": "nameserver 1.1.1.1\n",
					}),
					Receipt: &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}},
					Scope:   ImportScope{FromPath: "/src", ToPath: "/work"},
				}},
			},
			{Stage: "install", Index: fixtureIndex(installed)},
		}

		imports, err := producerContextImports(ctx, snapshots, packages, indexes)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bound := make([]string, 0, len(imports))
		for _, imported := range imports {
			bound = append(bound, imported.Path)
		}
		gomega.Expect(bound).To(gomega.ConsistOf(
			"/work/marker", "/work/hostname", "/work/hosts", "/work/resolv.conf",
		), "only where the import landed its files")
	})

	// A contradiction is still refused: a binding naming an original no package of this
	// context holds is not a thing to pass over in silence.
	ginkgo.It("refuses a binding naming an original outside the context packages", func() {
		_, resolved := declaredContextSource("registry.example.com/sources/tool", "tool-source", map[string]string{"/src/one.c": "one body"})
		packages, _ := contextPackages(resolved)
		index := fixtureIndex(map[string]string{"/work/one.c": "one body"})
		matches := originalMatches{"/work/one.c": {{Source: resolved.ID, Path: "src/one.c"}}}

		_, err := contextImports(index, matches, map[string]int{})

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("invalid: no context package for original source")))
		gomega.Expect(packages).NotTo(gomega.BeEmpty())
	})
})
