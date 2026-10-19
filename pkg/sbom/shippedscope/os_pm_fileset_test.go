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
