package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const partialInterp = "/lib64/ld-linux-x86-64.so.2"

// recordedDynamicELF is a dynamic file carrying the build record of its own build, which
// is what the gate asks of every compiled file before it reads a closure at all.
func recordedDynamicELF(interpreter, soname string, needed []string) []byte {
	note := fixtureRecordNote(fixtureBuildRecord(elf.ET_DYN))

	return elfFile(elf.EM_X86_64, elf.ELFCLASS64, interpreter, soname, needed, nil,
		[]extraSection{{name: ".note.package", kind: elf.SHT_NOTE, flags: elf.SHF_ALLOC, body: note}})
}

// searchingELF is a dynamic x86-64 file stating one search path of its own.
func searchingELF(interpreter, soname string, needed []string, tag elf.DynTag, value string) []byte {
	return elfFile(elf.EM_X86_64, elf.ELFCLASS64, interpreter, soname, needed, nil, nil, dynamicPath{tag: tag, value: value})
}

var _ = ginkgo.Describe("an image declared a part of a runtime closure", func() {
	// The C core builds libgcc_s and libstdc++ as scratch images holding one shared
	// object each: nothing in them is executed, so nothing in them names a loader, and
	// the closure they belong to is read in the image they are assembled into.
	ginkgo.It("accepts a shared object whose loader is in the image this one is assembled into", func() {
		files := map[string][]byte{
			"/usr/lib/libgcc_s.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libgcc_s.so.1", []string{"libc.so.6"}),
		}

		fs, present := nativeFilesystem(files)
		_, _, whole := runtimeDependencies(fs, present, false)
		gomega.Expect(whole).To(gomega.MatchError(gomega.ContainSubstring(
			"no-data: /usr/lib/libgcc_s.so.1 is dynamically linked and no executable of this image names a runtime loader")))

		fs, present = nativeFilesystem(files)
		edges, unresolved, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
		gomega.Expect(unresolved).To(gomega.ConsistOf("libc.so.6"))
	})

	// The binutils and gcc fragments do hold executables, which name the loader of the
	// glibc they are assembled beside. Both the loader and the objects they need are
	// that other image's, and the names they were asked for are what this one states.
	ginkgo.It("accepts an executable naming a loader no file of this image is", func() {
		files := map[string][]byte{
			"/usr/bin/ld": namedELF(elf.EM_X86_64, elf.ELFCLASS64, partialInterp, "", []string{"libc.so.6"}),
		}

		fs, present := nativeFilesystem(files)
		_, _, whole := runtimeDependencies(fs, present, false)
		gomega.Expect(whole).To(gomega.MatchError(gomega.ContainSubstring("missing runtime loader " + partialInterp)))

		fs, present = nativeFilesystem(files)
		edges, unresolved, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
		gomega.Expect(unresolved).To(gomega.ConsistOf("libc.so.6", partialInterp))
	})

	// Nothing about the absence of a loader makes an inherited search path readable.
	ginkgo.It("refuses DT_RPATH in a partial runtime as in any other image", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/ld": searchingELF(partialInterp, "", []string{"libfoo.so.1"}, elf.DT_RPATH, "/opt/lib"),
		})

		_, _, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("DT_RPATH inheritance unsupported")))
	})

	// What the image does hold is read as it always was: a file found where the name
	// was searched for, answering to another name, is the wrong file here too.
	ginkgo.It("refuses a found dependency that answers to another name", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/ld":          searchingELF(partialInterp, "", []string{"libfoo.so.1"}, elf.DT_RUNPATH, "/opt/lib"),
			"/opt/lib/libfoo.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libbar.so.2", nil),
		})

		_, _, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("runtime SONAME mismatch /opt/lib/libfoo.so.1")))
	})

	// The cache answers before any directory does, so an image holding one could be
	// resolved past this model unnoticed - a loader of its own to name the path is
	// what a partial runtime lacks, not a reason to stop looking for it.
	ginkgo.It("refuses the loader cache an image holds while its loader is elsewhere", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/lib/libgcc_s.so.1": namedELF(elf.EM_X86_64, elf.ELFCLASS64, "", "libgcc_s.so.1", []string{"libc.so.6"}),
		})
		fs.index.Files["/etc/ld.so.cache"] = shippedscope.File{}

		_, _, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader feature /etc/ld.so.cache")))
	})

	// An image holding the loader its executables name states where every name of
	// theirs resolves, so the declaration would excuse absences it does not have.
	ginkgo.It("refuses the declaration on an image holding the loader its executables name", func() {
		fs, present := nativeFilesystem(map[string][]byte{
			"/usr/bin/ld": namedELF(elf.EM_X86_64, elf.ELFCLASS64, partialInterp, "", []string{"libfoo.so.1"}),
			partialInterp: loaderELF("ld-linux-x86-64.so.2", "/opt/lib/"),
		})

		_, _, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: this image declares a partial runtime but holds the runtime loader " + partialInterp)))
	})

	// A static image resolves nothing anywhere, so the declaration excuses nothing.
	ginkgo.It("refuses the declaration on an image with no name to resolve elsewhere", func() {
		fs, present := nativeFilesystem(map[string][]byte{"/usr/bin/ld": minimalRuntimeELF(elf.ET_EXEC)})

		edges, unresolved, whole := runtimeDependencies(fs, present, false)
		gomega.Expect(whole).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
		gomega.Expect(unresolved).To(gomega.BeEmpty())

		_, _, err := runtimeDependencies(fs, present, true)

		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: this image declares a partial runtime, and every runtime name its files state resolves inside it")))
	})

	// The names are published in one order whatever order they were met in, so that
	// the document of an unchanged image is the same document.
	ginkgo.It("publishes the unresolved names sorted", func() {
		property, err := partialRuntimeClosureProperty([]string{"libstdc++.so.6", partialInterp, "libc.so.6"})

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(property.Name).To(gomega.Equal("dk:runtime-closure/v1"))
		gomega.Expect(property.Value).To(gomega.Equal(
			`{"schema":"dk:runtime-closure/v1","closure":"partial","unresolved":["` + partialInterp + `","libc.so.6","libstdc++.so.6"]}`))
	})

	// What was left open travels with the document, so that nobody reads it as the
	// statement of a whole closure.
	ginkgo.It("publishes on the document the names it resolved nothing for", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string]string{"/usr/lib/libgcc_s.so.1": string(recordedDynamicELF("", "libgcc_s.so.1", []string{"libc.so.6", "ld-linux-x86-64.so.2"}))})
		policy := fixturePolicy("libgcc-s")
		policy.Images["libgcc-s"] = ImagePolicy{Role: "final", PartialRuntime: true}
		bom := cdx.NewBOM()

		gomega.Expect(Apply(ctx, policy, "libgcc-s", img, nil, bom)).To(gomega.Succeed())

		published := map[string]string{}
		for _, property := range *bom.Metadata.Properties {
			published[property.Name] = property.Value
		}
		gomega.Expect(published).To(gomega.HaveKeyWithValue("dk:runtime-closure/v1",
			`{"schema":"dk:runtime-closure/v1","closure":"partial","unresolved":["ld-linux-x86-64.so.2","libc.so.6"]}`))
	})

	// The policy of the image is what carries the declaration into the gate, and a
	// document of an image that does not declare it says nothing of a closure.
	ginkgo.It("gates an image by what its own policy declares", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string]string{"/usr/bin/ld": string(minimalRuntimeELF(elf.ET_EXEC))})
		bom := cdx.NewBOM()

		gomega.Expect(Apply(ctx, fixturePolicy("libgcc-s"), "libgcc-s", img, nil, bom)).To(gomega.Succeed())
		for _, property := range *bom.Metadata.Properties {
			gomega.Expect(property.Name).NotTo(gomega.Equal("dk:runtime-closure/v1"))
		}

		partial := fixturePolicy("libgcc-s")
		partial.Images["libgcc-s"] = ImagePolicy{Role: "final", PartialRuntime: true}

		gomega.Expect(Apply(ctx, partial, "libgcc-s", img, nil, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: this image declares a partial runtime, and every runtime name its files state resolves inside it")))
	})
})

var _ = ginkgo.Describe("where a partial runtime may be declared", func() {
	// The flag relaxes what an image is held to, so it is the recipe's to state and
	// nobody else's: a policy file reaching the gate from outside the build could
	// otherwise excuse an image whose recipe never asked for it.
	ginkgo.It("refuses a policy file declaring an image a partial runtime", func(ctx ginkgo.SpecContext) {
		path := filepath.Join(ginkgo.GinkgoT().TempDir(), "policy.json")
		gomega.Expect(os.WriteFile(path, []byte(`{"schema":"dk.policy/v2","tools":[],"profiles":[],"images":{"libgcc-s":{"role":"final","outputs":[],"partialRuntime":true}}}`), 0o644)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("WERF_DK_NATIVE_POLICY", path)

		policy, _, err := Load(ctx)

		gomega.Expect(policy).To(gomega.BeNil())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(
			"invalid: partialRuntime of libgcc-s is declared by the image's recipe, not by a policy file")))
	})

	ginkgo.It("reads a policy file declaring none", func(ctx ginkgo.SpecContext) {
		path := filepath.Join(ginkgo.GinkgoT().TempDir(), "policy.json")
		gomega.Expect(os.WriteFile(path, []byte(`{"schema":"dk.policy/v2","tools":[],"profiles":[],"images":{"libgcc-s":{"role":"final","outputs":[]}}}`), 0o644)).To(gomega.Succeed())
		ginkgo.GinkgoT().Setenv("WERF_DK_NATIVE_POLICY", path)

		policy, _, err := Load(ctx)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(policy.Images["libgcc-s"].PartialRuntime).To(gomega.BeFalse())
	})
})

var _ = ginkgo.Describe("the identity of a partial runtime policy", func() {
	// An image declaring nothing marshals to what it always did, so nothing it has
	// already published is republished for this.
	ginkgo.It("states the flag in the policy only where it holds", func() {
		whole := NewDefaultPolicy(context.Background(), "app")
		partial := NewDefaultPolicy(context.Background(), "app")
		partial.Images["app"] = ImagePolicy{Role: "final", PartialRuntime: true}

		wholeBody, err := json.Marshal(whole)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		partialBody, err := json.Marshal(partial)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		gomega.Expect(string(wholeBody)).NotTo(gomega.ContainSubstring("partialRuntime"))
		gomega.Expect(string(partialBody)).To(gomega.ContainSubstring(`"partialRuntime":true`))
	})
})
