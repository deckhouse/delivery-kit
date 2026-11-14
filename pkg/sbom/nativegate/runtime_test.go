package nativegate

import (
	"context"
	"debug/elf"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("runtime dependencies", func() {
	ginkgo.It("resolves a name through the loader's directories and the links of the image", func() {
		edges, unresolved, err := baseImage().deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(unresolved).To(gomega.BeEmpty())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ConsistOf(loaderPath, "/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("searches the loader's directories in the order the loader holds them", func() {
		image := baseImage()
		image.files["/lib/libfoo.so.1.0"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		image.links["/lib/libfoo.so.1"] = "libfoo.so.1.0"
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/lib/libfoo.so.1.0"))
		gomega.Expect(edges["/usr/bin/app"]).NotTo(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("prefers a library in DT_RUNPATH to one in the loader's directories", func() {
		image := baseImage()
		image.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/opt/private"}.bytes()
		image.files["/opt/private/libfoo.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/opt/private/libfoo.so.1"))
		gomega.Expect(edges["/usr/bin/app"]).NotTo(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.DescribeTable("follows DT_RUNPATH before the loader's directories", func(runpath string) {
		image := baseImage()
		delete(image.files, "/usr/lib/libfoo.so.1.0")
		delete(image.links, "/usr/lib/libfoo.so.1")
		image.files["/opt/app/bin/tool"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: runpath}.bytes()
		delete(image.files, "/usr/bin/app")
		image.files["/opt/app/private/libfoo.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes()
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/opt/app/bin/tool"]).To(gomega.ContainElement("/opt/app/private/libfoo.so.1"))
	},
		ginkgo.Entry("$ORIGIN", "$ORIGIN/../private"),
		ginkgo.Entry("${ORIGIN}", "${ORIGIN}/../private"),
		ginkgo.Entry("absolute directory", "/opt/app/private"),
	)

	ginkgo.It("resolves a DT_NEEDED written as an absolute path, and through a directory link", func() {
		image := baseImage()
		image.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"/usr/lib64/libfoo.so.1.0"}}.bytes()
		image.links["/usr/lib64"] = "lib"
		edges, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges["/usr/bin/app"]).To(gomega.ContainElement("/usr/lib/libfoo.so.1.0"))
	})

	ginkgo.It("asks nothing of an image of static files", func() {
		image := &rtImage{files: map[string][]byte{"/usr/bin/static": dynELF{Type: elf.ET_EXEC}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
		edges, unresolved, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(edges).To(gomega.BeEmpty())
		gomega.Expect(unresolved).To(gomega.BeEmpty())
	})

	ginkgo.It("passes over a cross-built file that loads nothing", func() {
		image := baseImage()
		image.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64}.bytes()
		_, _, err := image.deps(false)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	})

	ginkgo.DescribeTable("refuses what it cannot resolve to one accounted file", func(change func(*rtImage), want string) {
		image := baseImage()
		change(image)
		_, _, err := image.deps(false)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(want)))
	},
		ginkgo.Entry("a missing library", func(i *rtImage) {
			delete(i.files, "/usr/lib/libfoo.so.1.0")
			delete(i.links, "/usr/lib/libfoo.so.1")
		}, "missing runtime dependency libfoo.so.1"),
		ginkgo.Entry("a library the SBOM does not account for", func(i *rtImage) { i.unknown["/usr/lib/libfoo.so.1.0"] = true }, "unknown runtime dependency /usr/lib/libfoo.so.1.0"),
		ginkgo.Entry("a library answering to another SONAME", func(i *rtImage) {
			i.files["/usr/lib/libfoo.so.1.0"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libbar.so.1"}}.bytes()
		}, "runtime SONAME mismatch"),
		ginkgo.Entry("a library that is not an ELF file", func(i *rtImage) {
			i.files["/usr/lib/libfoo.so.1.0"] = []byte("not elf")
			i.unknown["/usr/lib/libfoo.so.1.0"] = false
		}, "unknown runtime dependency"),
		ginkgo.Entry("a relative DT_NEEDED", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"lib/libfoo.so.1"}}.bytes()
		}, "relative DT_NEEDED unsupported lib/libfoo.so.1"),
		ginkgo.Entry("DT_RPATH", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Rpath: "/usr/lib"}.bytes()
		}, "DT_RPATH inheritance unsupported"),
		ginkgo.Entry("a RUNPATH variable other than ORIGIN", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/usr/$LIB"}.bytes()
		}, "unsupported runtime search path /usr/$LIB"),
		ginkgo.Entry("a relative RUNPATH directory", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "lib"}.bytes()
		}, "unsupported runtime search path lib"),
		ginkgo.Entry("a symbolic link cycle", func(i *rtImage) {
			i.links["/usr/lib/libfoo.so.1"] = "libfoo.so.1"
		}, "symlink cycle"),
		ginkgo.Entry("two libraries claiming one SONAME in a closure", func(i *rtImage) {
			i.files["/usr/bin/app"] = dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libx.so.1", "liby.so.1"}}.bytes()
			i.files["/usr/lib/libx.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libx.so.1", "shared.so.1"}}.bytes()
			i.files["/usr/lib/liby.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"liby.so.1", "shared.so.1"}}.bytes()
		}, "conflicting runtime SONAME shared.so.1"),
		ginkgo.Entry("an ELF file of an unsupported machine", func(i *rtImage) {
			i.files["/usr/bin/ppc"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_PPC64}.bytes()
		}, "unsupported runtime ELF architecture /usr/bin/ppc"),
		ginkgo.Entry("a cross-built file that needs a library", func(i *rtImage) {
			i.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64, Needed: []string{"libc.so.6"}}.bytes()
		}, "linux/arm64 executable needs libc.so.6"),
		ginkgo.Entry("a cross-built file that names a loader", func(i *rtImage) {
			i.files["/usr/bin/arm"] = dynELF{Type: elf.ET_EXEC, Machine: elf.EM_AARCH64, Interp: "/lib/ld-linux-aarch64.so.1"}.bytes()
		}, "linux/arm64 executable needs a runtime loader"),
	)

	ginkgo.DescribeTable("refuses an image whose loader it cannot state", func(change func(*rtImage), want string) {
		image := baseImage()
		change(image)
		_, _, err := image.deps(false)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(want)))
	},
		ginkgo.Entry("a loader the SBOM does not account for", func(i *rtImage) { i.unknown[loaderPath] = true }, "unknown runtime loader"),
		ginkgo.Entry("a loader changed after its record", func(i *rtImage) {
			i.recorded = map[string]string{loaderPath: fixtureDigest([]byte("the file the record describes"))}
		}, "hash-mismatch: the runtime loader /lib/ld-linux-x86-64.so.2"),
		ginkgo.Entry("a loader missing from the image", func(i *rtImage) { delete(i.files, loaderPath) }, "missing runtime loader"),
		ginkgo.Entry("a loader answering to another SONAME", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"libc.so.6"}, Rodata: []string{"/lib/", "/etc/ld.so.cache"}}.bytes()
		}, "runtime loader SONAME mismatch"),
		ginkgo.Entry("a loader stating no directories", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/etc/ld.so.cache"}}.bytes()
		}, "states no search directories"),
		ginkgo.Entry("a loader stating no cache", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/lib/"}}.bytes()
		}, "states no cache file"),
		ginkgo.Entry("a loader stating two caches", func(i *rtImage) {
			i.files[loaderPath] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-linux-x86-64.so.2"}, Rodata: []string{"/lib/", "/etc/ld.so.cache", "/var/ld.so.cache"}}.bytes()
		}, "states 2 cache files"),
		ginkgo.Entry("a loader that is not an ELF file", func(i *rtImage) { i.files[loaderPath] = []byte("#!/bin/sh") }, "unknown runtime loader"),
		ginkgo.Entry("two loaders in one image", func(i *rtImage) {
			i.files["/lib/ld-musl.so.1"] = dynELF{Type: elf.ET_DYN, Sonames: []string{"ld-musl.so.1"}, Rodata: []string{"/lib/", "/etc/ld.so.cache"}}.bytes()
			i.files["/usr/bin/other"] = dynELF{Type: elf.ET_EXEC, Interp: "/lib/ld-musl.so.1"}.bytes()
		}, "names 2 runtime loaders"),
		ginkgo.Entry("a dynamic library and no executable that names a loader", func(i *rtImage) {
			delete(i.files, "/usr/bin/app")
		}, "no executable of this image names a runtime loader"),
		ginkgo.Entry("the loader's cache in the image", func(i *rtImage) { i.files["/etc/ld.so.cache"] = []byte("cache") }, "unsupported dynamic loader feature /etc/ld.so.cache"),
		ginkgo.Entry("the loader's cache behind a link", func(i *rtImage) {
			i.files["/var/cache/ld.so.cache"] = []byte("cache")
			i.links["/etc"] = "/var/cache"
		}, "unsupported dynamic loader feature /etc/ld.so.cache"),
		ginkgo.Entry("a preload list", func(i *rtImage) { i.files["/etc/ld.so.preload"] = []byte("/usr/lib/libhook.so") }, "unsupported dynamic loader feature /etc/ld.so.preload"),
		ginkgo.Entry("glibc-hwcaps directories", func(i *rtImage) { i.files["/usr/lib/glibc-hwcaps/x86-64-v3/libfoo.so.1"] = []byte("x") }, "unsupported dynamic loader feature"),
	)

	ginkgo.Describe("a partial runtime", func() {
		ginkgo.It("excuses only the names no file of the image answers", func() {
			image := &rtImage{files: map[string][]byte{"/usr/bin/app": dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libc.so.6"}}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
			_, unresolved, err := image.deps(true)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(unresolved).To(gomega.ConsistOf("libc.so.6", interpName))
		})

		ginkgo.It("is refused where the image holds the loader its executables name", func() {
			_, _, err := baseImage().deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("declares a partial runtime but holds the runtime loader")))
		})

		ginkgo.It("is refused where every name resolves inside the image", func() {
			image := &rtImage{files: map[string][]byte{"/usr/bin/static": dynELF{Type: elf.ET_EXEC, Dynamic: true}.bytes()}, links: map[string]string{}, unknown: map[string]bool{}}
			_, _, err := image.deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("every runtime name its files state resolves inside it")))
		})

		ginkgo.It("still refuses a library the SBOM does not account for", func() {
			image := &rtImage{files: map[string][]byte{
				"/usr/bin/app":         dynELF{Type: elf.ET_EXEC, Interp: interpName, Needed: []string{"libfoo.so.1"}, Runpath: "/usr/lib"}.bytes(),
				"/usr/lib/libfoo.so.1": dynELF{Type: elf.ET_DYN, Sonames: []string{"libfoo.so.1"}}.bytes(),
			}, links: map[string]string{}, unknown: map[string]bool{"/usr/lib/libfoo.so.1": true}}
			_, _, err := image.deps(true)
			gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unknown runtime dependency /usr/lib/libfoo.so.1")))
		})
	})
})

var _ = ginkgo.Describe("the dynamic loader environment of an image", func() {
	verify := func(env ...string) error {
		ginkgo.GinkgoHelper()
		img := fixtureImage(nil)
		cfg, err := img.ConfigFile()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		cfg.Config.Env = env
		img, err = mutate.ConfigFile(img, cfg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		return Verify(context.Background(), img, cdx.NewBOM(), VerifyOptions{Platform: "linux/amd64", Subject: "app"})
	}

	ginkgo.DescribeTable("refuses a variable that changes what the loader loads", func(variable string) {
		err := verify("PATH=/usr/bin", variable+"=/opt/lib")
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader environment " + variable)))
	}, ginkgo.Entry("LD_LIBRARY_PATH", "LD_LIBRARY_PATH"), ginkgo.Entry("LD_PRELOAD", "LD_PRELOAD"), ginkgo.Entry("LD_AUDIT", "LD_AUDIT"))

	ginkgo.It("accepts an empty value, other variables and a name that only starts like one", func() {
		gomega.Expect(verify("PATH=/usr/bin", "LD_LIBRARY_PATH=", "LD_LIBRARY_PATH_NOTE=x", "LD_DEBUG=libs", strings.Repeat("A", 3)+"=b")).To(gomega.Succeed())
	})
})
