package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CollectFilesets, os-pm", func() {
	It("takes the files and symlinks the package manager recorded", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/git", "git"),
			regularFile("usr/lib64/libz.so.1.3.1", "zlib"),
			symlink("usr/lib64/libz.so.1", "libz.so.1.3.1"),
			regularFile("var/lib/pm/files.json", `{
				"git": {"version": "2.50.1", "files": {"/usr/bin/git": "sha256:dead"}},
				"zlib": {
					"version": "1.3.1",
					"files": {"/usr/lib64/libz.so.1.3.1": "sha256:beef"},
					"symlinks": {"/usr/lib64/libz.so.1": "libz.so.1.3.1"}
				}
			}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		git := filesetOf(filesets, EcosystemOSPM, "git", "2.50.1")
		Expect(git).NotTo(BeNil())
		Expect(git.Files).To(HaveKey("/usr/bin/git"))

		zlib := filesetOf(filesets, EcosystemOSPM, "zlib", "1.3.1")
		Expect(zlib).NotTo(BeNil())
		Expect(zlib.Files).To(HaveKey("/usr/lib64/libz.so.1.3.1"))
		Expect(zlib.Symlinks).To(HaveKeyWithValue("/usr/lib64/libz.so.1", "libz.so.1.3.1"))
	})

	It("finds a file the package manager recorded under a directory the image symlinks elsewhere", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			symlink("lib64", "/usr/lib"),
			symlink("usr/lib64", "/usr/lib"),
			symlink("usr/local/lib", "../lib"),
			symlink("opt/lib64", "/usr/lib64"),
			symlink("a", "x/link/.."),
			symlink("x/link", "/y/z"),
			symlink("loop", "/loop/again"),
			regularFile("usr/lib/libc.so.6", "libc"),
			regularFile("usr/lib/libcrypto.so.3", "libcrypto"),
			regularFile("usr/lib/libz.so.1.3.1", "zlib"),
			symlink("usr/lib/libz.so.1", "libz.so.1.3.1"),
			regularFile("usr/lib/libgcc_s.so.1", "libgcc"),
			regularFile("y/lib.so", "y"),
			regularFile("x/lib.so", "x"),
			regularFile("var/lib/pm/files.json", `{
				"libc": {"version": "2.43", "files": {"/lib64/libc.so.6": "sha256:dead"}},
				"openssl": {"version": "3.6.2", "files": {"/usr/lib64/libcrypto.so.3": "sha256:beef"}},
				"zlib": {
					"version": "1.3.1",
					"files": {"/usr/local/lib/libz.so.1.3.1": "sha256:cafe"},
					"symlinks": {"/usr/local/lib/libz.so.1": "libz.so.1.3.1"}
				},
				"gcc": {"version": "16.1.0", "files": {"/opt/lib64/libgcc_s.so.1": "sha256:f00d"}},
				"dotdot": {"version": "1", "files": {"/a/lib.so": "sha256:0101"}},
				"loop": {"version": "1", "files": {"/loop/lib.so": "sha256:1010"}}
			}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		libc := filesetOf(filesets, EcosystemOSPM, "libc", "2.43")
		Expect(libc).NotTo(BeNil())
		Expect(libc.Files).To(HaveKeyWithValue("/usr/lib/libc.so.6", HaveField("Digest", digestOf("libc"))),
			"the archive said /lib64, the image put it where /lib64 points")
		Expect(libc.Files).NotTo(HaveKey("/lib64/libc.so.6"))

		openssl := filesetOf(filesets, EcosystemOSPM, "openssl", "3.6.2")
		Expect(openssl).NotTo(BeNil())
		Expect(openssl.Files).To(HaveKey("/usr/lib/libcrypto.so.3"))

		zlib := filesetOf(filesets, EcosystemOSPM, "zlib", "1.3.1")
		Expect(zlib).NotTo(BeNil())
		Expect(zlib.Files).To(HaveKey("/usr/lib/libz.so.1.3.1"), "a relative directory symlink resolves against its own parent")
		Expect(zlib.Symlinks).To(HaveKeyWithValue("/usr/lib/libz.so.1", "libz.so.1.3.1"),
			"the leaf stays the symlink it is; only the directories above it are followed")

		Expect(filesetOf(filesets, EcosystemOSPM, "gcc", "16.1.0").Files).To(HaveKey("/usr/lib/libgcc_s.so.1"),
			"a directory symlink pointing at another directory symlink is followed to the end")
		Expect(filesetOf(filesets, EcosystemOSPM, "dotdot", "1").Files).To(HaveKeyWithValue("/y/lib.so", HaveField("Digest", digestOf("y"))),
			"a .. in a target steps out of what the symlink before it resolved to, not out of its spelling")

		loop := filesetOf(filesets, EcosystemOSPM, "loop", "1")
		Expect(loop.Files).To(BeEmpty(), "a symlink chain that never settles yields nothing, and does not hang")
		Expect(loop.DeclaresFiles).To(BeTrue())
	})

	It("takes the digest the image holds, not the one the package manager recorded", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("etc/ssl/certs/ca-certificates.crt", "rebuilt after install"),
			regularFile("var/lib/pm/files.json",
				`{"ca-certificates": {"version": "20250419", "files": {"/etc/ssl/certs/ca-certificates.crt": "sha256:stale"}}}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		certs := filesetOf(filesets, EcosystemOSPM, "ca-certificates", "20250419")
		Expect(certs).NotTo(BeNil())
		Expect(certs.Files["/etc/ssl/certs/ca-certificates.crt"].Digest).To(Equal(digestOf("rebuilt after install")))
	})

	It("leaves out a recorded file the image no longer holds", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/git", "git"),
			regularFile("var/lib/pm/files.json",
				`{"git": {"version": "2.50.1", "files": {"/usr/bin/git": "sha256:dead", "/usr/share/doc/git/README": "sha256:gone"}}}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		git := filesetOf(filesets, EcosystemOSPM, "git", "2.50.1")
		Expect(git).NotTo(BeNil())
		Expect(git.Files).To(HaveLen(1))
		Expect(git.DeclaresFiles).To(BeTrue())
	})

	It("tells a package that recorded no files from one whose recorded files are gone", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("var/lib/pm/files.json",
				`{"build-essential": {"version": "12.9"}, "git": {"version": "2.50.1", "files": {"/usr/bin/git": "sha256:dead"}}}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesetOf(filesets, EcosystemOSPM, "build-essential", "12.9").DeclaresFiles).To(BeFalse())
		Expect(filesetOf(filesets, EcosystemOSPM, "git", "2.50.1").DeclaresFiles).To(BeTrue())
	})

	It("reads a file list the image reaches through a hardlink", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/git", "git"),
			regularFile("var/lib/pm/files.json.orig",
				`{"git": {"version": "2.50.1", "files": {"/usr/bin/git": "sha256:dead"}}}`),
			hardlink("var/lib/pm/files.json", "var/lib/pm/files.json.orig"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets.OSPMFileListMissing).To(BeFalse())
		Expect(filesetOf(filesets, EcosystemOSPM, "git", "2.50.1")).NotTo(BeNil())
	})

	It("reads a file list a layer hardlinks to a file another layer wrote", func(ctx SpecContext) {
		img, err := imageOf(
			[]tarEntry{
				regularFile("usr/bin/git", "git"),
				regularFile("var/lib/pm/files.json.orig",
					`{"git": {"version": "2.50.1", "files": {"/usr/bin/git": "sha256:dead"}}}`),
			},
			[]tarEntry{
				hardlink("var/lib/pm/files.json", "var/lib/pm/files.json.orig"),
			},
		)
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets.OSPMFileListMissing).To(BeFalse())
		Expect(filesetOf(filesets, EcosystemOSPM, "git", "2.50.1")).NotTo(BeNil())
	})

	It("carries on without the file list an older package manager never wrote, and says so", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/git", "git"),
			regularFile("var/lib/pm/index.json", `{"git": {"name": "git", "version": "2.50.1"}}`),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets.Filesets).To(BeEmpty())
		Expect(filesets.OSPMFileListMissing).To(BeTrue())
	})

	It("does not mistake an image without os-pm packages for one missing its file list", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/git", "git"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		Expect(filesets.Filesets).To(BeEmpty())
		Expect(filesets.OSPMFileListMissing).To(BeFalse())
	})

	It("reports an image whose file list it cannot read", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("var/lib/pm/files.json", "{ this is not json"),
		})
		Expect(err).NotTo(HaveOccurred())

		_, err = CollectFilesets(ctx, img)
		Expect(err).To(MatchError(ContainSubstring("files.json")))
	})
})
