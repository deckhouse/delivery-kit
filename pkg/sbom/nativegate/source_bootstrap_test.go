package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"maps"
	"slices"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

// bootstrapHeader stands for a source file of the toolchain's own runtime: the prepared
// source serves it, the toolchain installs it at one path and copies it to another, and
// nothing compiled it, so only a mapping to the Packet can account for it.
const bootstrapHeader = "#define RUNTIME 1\n"

func bootstrapPolicy() *Policy {
	return &Policy{
		Schema:   "dk.policy/v2",
		Profiles: []string{"c-object", "c-static", "c-dynamic", "go"},
		Tools:    []Tool{{Name: "fixture-tool", Version: "1.0", SHA256: "sha256:" + strings.Repeat("2", 64)}},
		Images:   map[string]ImagePolicy{"app": {Role: "final"}},
	}
}

func bootstrapIndex(ctx context.Context, files map[string]string) *shippedscope.FileIndex {
	ginkgo.GinkgoHelper()
	index, err := shippedscope.IndexImageFiles(ctx, transportImage(files))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(index.Incomplete).To(gomega.BeFalse())

	return index
}

// bootstrapSourceFiles is the toolchain image an import takes files out of: a tool it
// built with a record of its own build, the runtime sources it was made from, and the
// copy of one of those headers it installs somewhere else entirely.
func bootstrapSourceFiles(tool []byte) map[string]string {
	return map[string]string{
		"/usr/local/go/pkg/tool/compile":   string(tool),
		"/usr/local/go/src/runtime/defs.h": bootstrapHeader,
		"/usr/local/go/pkg/include/defs.h": bootstrapHeader,
	}
}

func bootstrapImported(files map[string]string) map[string]string {
	imported := make(map[string]string, len(files))
	for name, body := range files {
		imported["/opt/go"+strings.TrimPrefix(name, "/usr/local/go")] = body
	}

	return imported
}

func bootstrapMappings() []ImportOriginal {
	return []ImportOriginal{
		{Root: "/usr/local/go/src", OriginalPath: "src", PackageName: "go", PackageVersion: "1.0"},
		{Root: "/usr/local/go/pkg/include", OriginalPath: "src/runtime", PackageName: "go", PackageVersion: "1.0"},
	}
}

// bootstrapOriginalPacket pushes the prepared source the toolchain was made from.
func bootstrapOriginalPacket(ctx context.Context) sources.Source {
	ginkgo.GinkgoHelper()

	return pushTransportOriginal(ctx, transportRegistryHost(ctx)+"/test/original", "go", map[string]string{
		"/src/runtime/defs.h":  bootstrapHeader,
		"/src/runtime/other.h": "#define OTHER 1\n",
	})
}

// bootstrapBuild runs a verification of an image whose install stage imported the given
// files out of a bootstrap source, under the given declared mappings. Each `later` file
// set is one more stage the build runs after that import, so a spec can state what a shell
// did to the imported files before the image was final.
func bootstrapBuild(ctx context.Context, sourceFiles map[string]string, originals []ImportOriginal, bom *cdx.BOM, later ...map[string]string) (*cdx.BOM, v1.Image, sources.Source, error) {
	ginkgo.GinkgoHelper()
	source := bootstrapOriginalPacket(ctx)

	from, _ := transportStage(ctx, "from", map[string]string{})
	install, image := transportStage(ctx, "install", bootstrapImported(sourceFiles))
	install.Imports = []SourceImport{{
		Index:     bootstrapIndex(ctx, sourceFiles),
		Receipt:   transportReceipt(source),
		BOM:       bom,
		Bootstrap: true,
		Originals: originals,
		Scope:     ImportScope{FromPath: "/usr/local/go", ToPath: "/opt/go"},
	}}
	snapshots := []SourceSnapshot{from, install}
	for _, files := range later {
		var snapshot SourceSnapshot
		snapshot, image = transportStage(ctx, "setup", files)
		snapshots = append(snapshots, snapshot)
	}

	target := cdx.NewBOM()
	err := ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image, snapshots, target, ApplySourceSnapshotsOptions{})

	return target, image, source, err
}

// bootstrapDeclaredBuild runs the same verification for a bootstrap source that opened no
// package of its own: the toolchain it ships was compiled from a prepared source its own
// recipe named, and only that declaration accounts for the files.
func bootstrapDeclaredBuild(ctx context.Context, sourceFiles map[string]string, originals []ImportOriginal, packages []sources.Source) (*cdx.BOM, error) {
	ginkgo.GinkgoHelper()
	from, _ := transportStage(ctx, "from", map[string]string{})
	install, image := transportStage(ctx, "install", bootstrapImported(sourceFiles))
	install.Imports = []SourceImport{{
		Index:     bootstrapIndex(ctx, sourceFiles),
		Bootstrap: true,
		Originals: originals,
		Packages:  packages,
		Scope:     ImportScope{FromPath: "/usr/local/go", ToPath: "/opt/go"},
	}}

	target := cdx.NewBOM()

	return target, ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image, []SourceSnapshot{from, install}, target, ApplySourceSnapshotsOptions{})
}

// bootstrapPublishedMarks reads back the paths a verified image publishes as received from
// a bootstrap source.
func bootstrapPublishedMarks(bom *cdx.BOM) []string {
	ginkgo.GinkgoHelper()
	marks, err := readBootstrapMarks(bom)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return slices.Sorted(maps.Keys(marks))
}

var _ = ginkgo.Describe("Files imported from a bootstrap source", func() {
	ginkgo.It("accounts for a compiled tool by its own build record and for a source file by the Packet it is mapped to", func(ctx ginkgo.SpecContext) {
		bom, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), bootstrapMappings(), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		records := transportRecords(bom)
		gomega.Expect(slices.Sorted(maps.Keys(records))).To(gomega.Equal([]string{
			"/opt/go/pkg/include/defs.h", "/opt/go/pkg/tool/compile", "/opt/go/src/runtime/defs.h",
		}))
		gomega.Expect(records["/opt/go/pkg/tool/compile"].Origin).To(gomega.Equal("build"))
		gomega.Expect(records["/opt/go/pkg/tool/compile"].Composition).NotTo(gomega.BeEmpty())

		catalog := transportOriginals(bom)
		id := onlyTransportSource(catalog)
		gomega.Expect(records["/opt/go/src/runtime/defs.h"].Owners).To(gomega.Equal([]string{id}))
		// The physical path and the path inside the Packet differ: only the mapping
		// says which bytes of the prepared source these are.
		gomega.Expect(catalog.Files["/opt/go/pkg/include/defs.h"].Bindings).
			To(gomega.Equal([]originalBinding{{Source: id, Path: "src/runtime/defs.h"}}))
	})

	ginkgo.It("refuses a file of the same bytes that no mapping places in the Packet", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/lib/extra.h"] = bootstrapHeader

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /opt/go/lib/extra.h comes from a bootstrap source with neither a build record nor an original binding")))
	})

	ginkgo.It("refuses a mapping that names other bytes of the Packet", func(ctx ginkgo.SpecContext) {
		mappings := bootstrapMappings()
		mappings[1].OriginalPath = "src"

		_, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), mappings, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /opt/go/pkg/include/defs.h comes from a bootstrap source")))
	})

	// The mapping names a path of the Packet, and that path has to hold these very
	// bytes: a file the toolchain patched is no longer the prepared source's.
	ginkgo.It("refuses a file whose mapped path in the Packet holds other bytes", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/pkg/include/defs.h"] = "#define RUNTIME 2\n"

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /opt/go/pkg/include/defs.h comes from a bootstrap source with neither a build record nor an original binding")))
	})

	ginkgo.It("refuses a compiled artifact that carries no record of its build", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/pkg/tool/libfoo.a"] = "!<arch>\ndebian-binary"

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"/opt/go/pkg/tool/libfoo.a: invalid: the archive ends inside the header of entry 0")))
	})

	// A static library imported out of a bootstrap source is answered for the
	// way any other compiled artifact is: by the record of the build that made
	// it. An archive holds no such record, so its members hold them, and the
	// mark the import leaves on the path is met only when every one of them
	// does.
	ginkgo.It("accounts for an imported static archive by the records of its members", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/pkg/tool/libfoo.a"] = string(fixtureArchive(memberEntry("start", "first-object")))

		bom, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		record := transportRecords(bom)["/opt/go/pkg/tool/libfoo.a"]
		gomega.Expect(record.Archive.Members).To(gomega.HaveLen(1))
		gomega.Expect(record.Archive.Members[0].Name).To(gomega.Equal("start"))
		gomega.Expect(record.Components).To(gomega.HaveLen(1))
	})

	ginkgo.It("refuses an imported static archive a member of which carries no record", func(ctx ginkgo.SpecContext) {
		unrecorded := bytes.Replace(recordedMember("first-object"), []byte(".note.package"), []byte(".note.unknown"), 1)
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/pkg/tool/libfoo.a"] = string(fixtureArchive(archiveEntry{name: "start/", body: unrecorded}))

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"/opt/go/pkg/tool/libfoo.a: no-data: missing sbom metadata (archive member start, index 0)")))
	})

	// What a bootstrap image says about its own files - that it declares them its own
	// sources, that it generated them - is not read at all, so it can claim nothing.
	ginkgo.It("reads no document of the bootstrap source itself", func(ctx ginkgo.SpecContext) {
		claimed := baseWithOriginals(originalsCatalog{Schema: originalsProperty, Sources: map[string]sources.Source{}, Files: map[string]originalFileRecord{}})

		_, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), bootstrapMappings(), claimed)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: a bootstrap import source describes no composition of its own")))
	})

	ginkgo.It("refuses a mapping to a prepared source the import source never opened", func(ctx ginkgo.SpecContext) {
		mappings := bootstrapMappings()
		mappings[0].PackageVersion = "2.0"

		_, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), mappings, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: the bootstrap import source opens no prepared source go 2.0")))
	})

	ginkgo.It("refuses a declared root that is not a rooted path of the source image", func(ctx ginkgo.SpecContext) {
		mappings := bootstrapMappings()
		mappings[0].Root = "usr/local/go/src"

		_, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), mappings, nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("is not a clean rooted path")))
	})

	ginkgo.It("publishes the paths it received, so the chain below it answers for them too", func(ctx ginkgo.SpecContext) {
		bom, _, _, err := bootstrapBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), bootstrapMappings(), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bootstrapPublishedMarks(bom)).To(gomega.Equal([]string{
			"/opt/go/pkg/include/defs.h", "/opt/go/pkg/tool/compile", "/opt/go/src/runtime/defs.h",
		}))
	})

	// The obligation is on the path, not on the bytes standing at it: rewriting the file
	// does not end it, and the rewritten file no longer is what the prepared source serves.
	ginkgo.It("refuses a mapped file a later stage rewrote in place", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		patched := bootstrapImported(files)
		patched["/opt/go/src/runtime/defs.h"] = "#define RUNTIME 2\n"

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil, patched)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"hash-mismatch: /opt/go/src/runtime/defs.h comes from a bootstrap source and no longer holds the bytes of the original it was bound to")))
	})

	ginkgo.It("refuses an unmapped file a later stage rewrote in place", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/lib/extra.h"] = "#define EXTRA 1\n"
		appended := bootstrapImported(files)
		appended["/opt/go/lib/extra.h"] = "#define EXTRA 1\n\n"

		_, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil, appended)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /opt/go/lib/extra.h comes from a bootstrap source with neither a build record nor an original binding")))
	})

	ginkgo.It("lets go of a path the build deleted", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/lib/extra.h"] = "#define EXTRA 1\n"
		removed := bootstrapImported(files)
		delete(removed, "/opt/go/lib/extra.h")

		bom, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil, removed)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bootstrapPublishedMarks(bom)).NotTo(gomega.ContainElement("/opt/go/lib/extra.h"))
	})

	// DK does not promise to track content a shell moved: the boundary there is the
	// trusted producer. Marking every equal-byte file instead would refuse unrelated
	// files that merely happen to be identical.
	ginkgo.It("does not follow the bytes a later stage copied to another path", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		copied := bootstrapImported(files)
		copied["/srv/defs.h"] = bootstrapHeader

		bom, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil, copied)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bootstrapPublishedMarks(bom)).NotTo(gomega.ContainElement("/srv/defs.h"))
	})
})

var _ = ginkgo.Describe("Files of a bootstrap source its own recipe compiled", func() {
	// A toolchain that builds itself installs no package receipt for the source it was
	// made from: what accounts for those files is the prepared source its own recipe
	// declares its stages compile, resolved against that pinned Packet.
	ginkgo.It("accounts for a mapped file by the prepared source the bootstrap recipe declares", func(ctx ginkgo.SpecContext) {
		declared := bootstrapOriginalPacket(ctx)

		bom, err := bootstrapDeclaredBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), bootstrapMappings(), []sources.Source{declared})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(transportRecords(bom)))).To(gomega.Equal([]string{
			"/opt/go/pkg/include/defs.h", "/opt/go/pkg/tool/compile", "/opt/go/src/runtime/defs.h",
		}))
	})

	ginkgo.It("refuses a file no mapping places in that prepared source", func(ctx ginkgo.SpecContext) {
		declared := bootstrapOriginalPacket(ctx)
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		files["/usr/local/go/lib/extra.h"] = bootstrapHeader

		_, err := bootstrapDeclaredBuild(ctx, files, bootstrapMappings(), []sources.Source{declared})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /opt/go/lib/extra.h comes from a bootstrap source with neither a build record nor an original binding")))
	})

	ginkgo.It("refuses a mapping no declared source and no receipt accounts for", func(ctx ginkgo.SpecContext) {
		declared := bootstrapOriginalPacket(ctx)
		mappings := bootstrapMappings()
		mappings[0].PackageVersion = "2.0"

		_, err := bootstrapDeclaredBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), mappings, []sources.Source{declared})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: the bootstrap import source opens no prepared source go 2.0")))
	})

	ginkgo.It("refuses a bootstrap source that stands on nothing at all", func(ctx ginkgo.SpecContext) {
		_, err := bootstrapDeclaredBuild(ctx, bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC)), bootstrapMappings(), nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: the bootstrap import source carries neither an original source receipt nor a declared prepared source")))
	})

	// The two accounts of one name have to be the same prepared source; picking either
	// of two would be picking the convenient one.
	ginkgo.It("refuses a name the receipt and the recipe disagree about", func(ctx ginkgo.SpecContext) {
		installed := bootstrapOriginalPacket(ctx)
		other := pushTransportOriginal(ctx, transportRegistryHost(ctx)+"/test/other", "go", map[string]string{
			"/src/runtime/defs.h": bootstrapHeader,
		})

		from, _ := transportStage(ctx, "from", map[string]string{})
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		install, image := transportStage(ctx, "install", bootstrapImported(files))
		install.Imports = []SourceImport{{
			Index:     bootstrapIndex(ctx, files),
			Receipt:   transportReceipt(installed),
			Bootstrap: true,
			Originals: bootstrapMappings(),
			Packages:  []sources.Source{other},
			Scope:     ImportScope{FromPath: "/usr/local/go", ToPath: "/opt/go"},
		}}

		err := ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from, install}, cdx.NewBOM(), ApplySourceSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: the bootstrap import source stands on two different prepared sources named go 1.0")))
	})
})

var _ = ginkgo.Describe("Files a chain received from a bootstrap source", func() {
	// What the toolchain's files are does not become unknowable one image later: an
	// image built FROM one that received them answers for them exactly as it does.
	ginkgo.It("refuses a marked file a descendant image rewrote", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		base, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		from, _ := transportStage(ctx, "from", bootstrapImported(files))
		patched := bootstrapImported(files)
		patched["/opt/go/src/runtime/defs.h"] = "#define RUNTIME 2\n"
		setup, image := transportStage(ctx, "setup", patched)

		err = ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from, setup}, cdx.NewBOM(), ApplySourceSnapshotsOptions{BaseBOM: base})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"hash-mismatch: /opt/go/src/runtime/defs.h comes from a bootstrap source and no longer holds the bytes of the original it was bound to")))
	})

	ginkgo.It("keeps the obligation on a path a third image imported out of the second", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		second, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		from, _ := transportStage(ctx, "from", map[string]string{})
		landed := map[string]string{}
		for name, body := range bootstrapImported(files) {
			landed["/srv"+name] = body
		}
		install, _ := transportStage(ctx, "dependenciesBeforeInstall", landed)
		install.Imports = []SourceImport{{
			Index: bootstrapIndex(ctx, bootstrapImported(files)),
			BOM:   second,
			Scope: ImportScope{FromPath: "/opt/go", ToPath: "/srv/opt/go"},
		}}
		patched := maps.Clone(landed)
		patched["/srv/opt/go/src/runtime/defs.h"] = "#define RUNTIME 2\n"
		setup, image := transportStage(ctx, "setup", patched)

		err = ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from, install, setup}, cdx.NewBOM(), ApplySourceSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"hash-mismatch: /srv/opt/go/src/runtime/defs.h comes from a bootstrap source and no longer holds the bytes of the original it was bound to")))
	})

	ginkgo.It("refuses a published mark of a version it does not understand", func(ctx ginkgo.SpecContext) {
		files := bootstrapSourceFiles(minimalRuntimeELF(elf.ET_EXEC))
		base, _, _, err := bootstrapBuild(ctx, files, bootstrapMappings(), nil)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		properties := append([]cdx.Property{}, *base.Metadata.Properties...)
		properties = append(properties, cdx.Property{Name: "dk:bootstrap/v2", Value: "{}"})
		base.Metadata.Properties = &properties

		from, image := transportStage(ctx, "from", bootstrapImported(files))

		err = ApplySourceSnapshots(ctx, bootstrapPolicy(), "app", image,
			[]SourceSnapshot{from}, cdx.NewBOM(), ApplySourceSnapshotsOptions{BaseBOM: base})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported inherited bootstrap marks property dk:bootstrap/v2")))
	})
})
