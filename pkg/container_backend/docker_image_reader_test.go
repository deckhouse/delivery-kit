package container_backend

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("fileTarCollector", func() {
	type entry struct {
		name     string
		typeflag byte
		content  string
		linkname string
	}

	// feed mimics what `docker cp <path>` streams: the requested object first, named
	// by its base name, followed by whatever it contains.
	feed := func(collect func(*tar.Reader, *tar.Header) error, entries []entry) error {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Linkname: e.linkname}
			if e.typeflag == tar.TypeReg {
				hdr.Size = int64(len(e.content))
			}
			Expect(tw.WriteHeader(hdr)).To(Succeed())
			if e.typeflag == tar.TypeReg {
				_, err := tw.Write([]byte(e.content))
				Expect(err).To(Succeed())
			}
		}
		Expect(tw.Close()).To(Succeed())

		tr := tar.NewReader(&buf)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				return nil
			}
			Expect(err).To(Succeed())
			if err := collect(tr, hdr); err != nil {
				return err
			}
		}
	}

	It("reads the requested regular file", func() {
		collector := &fileTarCollector{path: "/out/ext.roothash", imageRef: "image"}

		Expect(feed(collector.collect, []entry{
			{name: "ext.roothash", typeflag: tar.TypeReg, content: "roothash"},
		})).To(Succeed())
		Expect(collector.result()).To(Equal([]byte("roothash")))
	})

	It("refuses a directory instead of returning a file it contains", func() {
		collector := &fileTarCollector{path: "/out", imageRef: "image"}

		err := feed(collector.collect, []entry{
			{name: "out/", typeflag: tar.TypeDir},
			{name: "out/ext.roothash", typeflag: tar.TypeReg, content: "roothash"},
		})
		Expect(err).To(MatchError(ContainSubstring(`/out in image "image" is a directory`)))
	})

	It("reports a path that holds no regular file as not existing", func() {
		collector := &fileTarCollector{path: "/out/link", imageRef: "image"}

		Expect(feed(collector.collect, []entry{
			{name: "link", typeflag: tar.TypeSymlink, linkname: "/elsewhere"},
		})).To(Succeed())

		_, err := collector.result()
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	Describe("globTarCollector", func() {
		It("rebases the entries of the copied base directory onto the image path and keeps the regular files the pattern matches, hard links included, sorted", func() {
			collector := newGlobTarCollector("/out/lib/modules/**/*.ko")
			Expect(collector.base).To(Equal("/out/lib/modules"))

			Expect(feed(collector.collect, []entry{
				{name: "modules", typeflag: tar.TypeDir},
				{name: "modules/6.12", typeflag: tar.TypeDir},
				{name: "modules/6.12/kernel/net/b.ko", typeflag: tar.TypeReg, content: "b"},
				{name: "modules/6.12/kernel/a.ko", typeflag: tar.TypeReg, content: "a"},
				{name: "modules/6.12/modules.order", typeflag: tar.TypeReg, content: "order"},
				{name: "modules/6.12/kernel/link.ko", typeflag: tar.TypeSymlink, linkname: "a.ko"},
				{name: "modules/6.12/kernel/hard.ko", typeflag: tar.TypeLink, linkname: "modules/6.12/kernel/a.ko"},
				{name: "modules/6.12/kernel/hard-to-link.ko", typeflag: tar.TypeLink, linkname: "modules/6.12/kernel/link.ko"},
			})).To(Succeed())

			Expect(collector.result()).To(Equal([]string{
				"/out/lib/modules/6.12/kernel/a.ko",
				"/out/lib/modules/6.12/kernel/hard.ko",
				"/out/lib/modules/6.12/kernel/net/b.ko",
			}), "a hard link to a regular file is that file under another name; a hard link to a symlink is not")
		})

		It("matches a file directly under the base directory when the pattern allows it", func() {
			collector := newGlobTarCollector("/out/*.roothash")

			Expect(feed(collector.collect, []entry{
				{name: "out", typeflag: tar.TypeDir},
				{name: "out/ext.roothash", typeflag: tar.TypeReg, content: "x"},
				{name: "out/sub/ext.roothash", typeflag: tar.TypeReg, content: "y"},
			})).To(Succeed())

			Expect(collector.result()).To(Equal([]string{"/out/ext.roothash"}))
		})
	})
})
