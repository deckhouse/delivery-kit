package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CollectFilesets, Python", func() {
	It("splits a namespace directory between the distributions that declare its files", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/google/auth/__init__.py", "auth"),
			regularFile("usr/lib/python3.12/site-packages/google/protobuf/__init__.py", "proto"),
			regularFile("usr/lib/python3.12/site-packages/google_auth-2.41.0.dist-info/RECORD",
				"google/auth/__init__.py,sha256=aaa,4\n"),
			regularFile("usr/lib/python3.12/site-packages/protobuf-6.33.0.dist-info/RECORD",
				"google/protobuf/__init__.py,sha256=bbb,5\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		auth := filesetOf(filesets, EcosystemPython, "google-auth", "2.41.0")
		Expect(auth).NotTo(BeNil())
		Expect(auth.Files).To(HaveKey("/usr/lib/python3.12/site-packages/google/auth/__init__.py"))
		Expect(auth.Files).NotTo(HaveKey("/usr/lib/python3.12/site-packages/google/protobuf/__init__.py"))

		protobuf := filesetOf(filesets, EcosystemPython, "protobuf", "6.33.0")
		Expect(protobuf).NotTo(BeNil())
		Expect(protobuf.Files).To(HaveLen(1))
	})

	It("names the distribution the way PEP 503 spells it, not the way its metadata does", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/typing_extensions.py", "typing"),
			regularFile("usr/lib/python3.12/site-packages/Typing_Extensions-4.12.2.dist-info/RECORD",
				"typing_extensions.py,sha256=aaa,6\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		typing := filesetOf(filesets, EcosystemPython, "typing-extensions", "4.12.2")
		Expect(typing).NotTo(BeNil())
		Expect(typing.Files).To(HaveKey("/usr/lib/python3.12/site-packages/typing_extensions.py"))
	})

	It("credits a compiled file to the source its distribution declares, and to no other", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/yaml/__init__.py", "yaml"),
			regularFile("usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.pyc", "compiled"),
			regularFile("usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.opt-1.pyc", "optimized"),
			regularFile("usr/lib/python3.12/site-packages/PyYAML-6.0.2.dist-info/RECORD",
				"yaml/__init__.py,sha256=aaa,4\n"),
			regularFile("usr/lib/python3.12/site-packages/six.py", "six"),
			regularFile("usr/lib/python3.12/site-packages/__pycache__/six.cpython-312.pyc", "compiled six"),
			regularFile("usr/lib/python3.12/site-packages/six-1.17.0.dist-info/RECORD",
				"six.py,sha256=bbb,3\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		pyyaml := filesetOf(filesets, EcosystemPython, "pyyaml", "6.0.2")
		Expect(pyyaml).NotTo(BeNil())
		Expect(pyyaml.Files).To(HaveKey("/usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.pyc"))
		Expect(pyyaml.Files).To(HaveKey("/usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.opt-1.pyc"))
		Expect(pyyaml.Files).NotTo(HaveKey("/usr/lib/python3.12/site-packages/__pycache__/six.cpython-312.pyc"))

		six := filesetOf(filesets, EcosystemPython, "six", "1.17.0")
		Expect(six).NotTo(BeNil())
		Expect(six.Files).To(HaveLen(2))
	})

	It("reads a record whose path is quoted because it holds a comma", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/odd/a,b.txt", "odd"),
			regularFile("usr/lib/python3.12/site-packages/odd-1.0.dist-info/RECORD",
				"\"odd/a,b.txt\",sha256=aaa,3\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		odd := filesetOf(filesets, EcosystemPython, "odd", "1.0")
		Expect(odd).NotTo(BeNil())
		Expect(odd.Files).To(HaveKey("/usr/lib/python3.12/site-packages/odd/a,b.txt"))
	})

	It("keeps the compiled file when the source it was built from is gone", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.pyc", "compiled"),
			regularFile("usr/lib/python3.12/site-packages/PyYAML-6.0.2.dist-info/RECORD",
				"yaml/__init__.py,sha256=aaa,4\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		pyyaml := filesetOf(filesets, EcosystemPython, "pyyaml", "6.0.2")
		Expect(pyyaml).NotTo(BeNil())
		Expect(pyyaml.Files).To(HaveLen(1))
		Expect(pyyaml.Files).To(HaveKey("/usr/lib/python3.12/site-packages/yaml/__pycache__/__init__.cpython-312.pyc"))
	})

	It("follows a record out of the site directory and keeps a declared symlink", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/bin/pytest", "entrypoint"),
			symlink("usr/lib/python3.12/site-packages/pytest/shortcut", "/usr/bin/pytest"),
			regularFile("usr/lib/python3.12/site-packages/pytest-8.4.2.dist-info/RECORD",
				"../../../bin/pytest,sha256=aaa,10\npytest/shortcut,,\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		pytest := filesetOf(filesets, EcosystemPython, "pytest", "8.4.2")
		Expect(pytest).NotTo(BeNil())
		Expect(pytest.Files).To(HaveKey("/usr/bin/pytest"))
		Expect(pytest.Symlinks).To(HaveKeyWithValue("/usr/lib/python3.12/site-packages/pytest/shortcut", "/usr/bin/pytest"))
	})

	It("leaves out records no longer in the image", func(ctx SpecContext) {
		img, err := imageOf([]tarEntry{
			regularFile("usr/lib/python3.12/site-packages/yaml/__init__.py", "yaml"),
			regularFile("usr/lib/python3.12/site-packages/PyYAML-6.0.2.dist-info/RECORD",
				"yaml/__init__.py,sha256=aaa,4\nyaml/removed.py,sha256=bbb,9\n"),
		})
		Expect(err).NotTo(HaveOccurred())

		filesets, err := CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())

		pyyaml := filesetOf(filesets, EcosystemPython, "pyyaml", "6.0.2")
		Expect(pyyaml).NotTo(BeNil())
		Expect(pyyaml.Files).To(HaveLen(1))
	})
})
