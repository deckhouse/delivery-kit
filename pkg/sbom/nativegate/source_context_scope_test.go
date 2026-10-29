package nativegate

import (
	"encoding/json"

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
