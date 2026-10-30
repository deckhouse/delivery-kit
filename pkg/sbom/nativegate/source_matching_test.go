package nativegate

import (
	"context"
	"maps"
	"slices"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func fixtureIndex(files map[string]string) *shippedscope.FileIndex {
	index, err := shippedscope.IndexImageFiles(context.Background(), fixtureImage(files))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return index
}

var _ = ginkgo.Describe("carrying original matches", func() {
	ginkgo.It("follows the bytes to a moved or copied path and leaves changed bytes unattributed", func() {
		before := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes", "/etc/conf": "conf-bytes", "/opt/gone": "gone-bytes"})
		after := fixtureIndex(map[string]string{"/usr/bin/tool": "tool-bytes", "/opt/tool": "tool-bytes", "/etc/conf": "patched-bytes"})
		matches := originalMatches{
			"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}},
			"/etc/conf": {{Source: "src-conf", Path: "etc/conf"}},
			"/opt/gone": {{Source: "src-gone", Path: "share/gone"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried).To(gomega.Equal(originalMatches{
			"/usr/bin/tool": {{Source: "src-tool", Path: "bin/tool"}},
			"/opt/tool":     {{Source: "src-tool", Path: "bin/tool"}},
		}))
	})

	// The function serves the gate's evidence chain as well as the producer context, so
	// the rule holds wherever it is called from: a file the stage did not touch is not
	// one of the files it is byte for byte.
	// The function serves the gate's evidence chain as well as the producer context, so
	// the rule holds wherever it is called from: a file the stage did not touch is not
	// one of the files it happens to be byte for byte. Here the base's own binary and
	// an imported one share their bytes, and only the imported one is attributed.
	ginkgo.It("leaves an untouched path alone though an imported path's bytes match it", func() {
		before := fixtureIndex(map[string]string{"/usr/bin/tool": "tool-bytes", "/bin/sh": "shell", "/opt/tool": "tool-bytes"})
		after := fixtureIndex(map[string]string{"/usr/bin/tool": "tool-bytes", "/bin/sh": "shell", "/opt/tool": "tool-bytes"})
		matches := originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}}

		carried, err := carryOriginalMatches(before, matches, after)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(carried))).To(gomega.Equal([]string{"/opt/tool"}),
			"the base's own binary was not imported from anywhere")
	})

	// The shape a real strict builder arrived in: the base holds an empty /.dockerenv
	// the container runtime wrote, and the packet several empty files of its own.
	ginkgo.It("binds no empty file of the base to the empty files an import carried", func() {
		before := fixtureIndex(map[string]string{
			"/.dockerenv": "", "/bin/sh": "shell",
			"/opt/empty_a": "", "/opt/empty_b": "",
		})
		after := fixtureIndex(map[string]string{
			"/.dockerenv": "", "/bin/sh": "shell",
			"/opt/empty_a": "", "/opt/empty_b": "",
		})
		matches := originalMatches{
			"/opt/empty_a": {{Source: "src-a", Path: "testdata/a"}},
			"/opt/empty_b": {{Source: "src-b", Path: "testdata/b"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried).To(gomega.Equal(originalMatches{
			"/opt/empty_a": {{Source: "src-a", Path: "testdata/a"}},
			"/opt/empty_b": {{Source: "src-b", Path: "testdata/b"}},
		}), "each keeps the evidence of its own import, and the runtime's file gains none")

		binding, err := uniqueOriginalBinding(carried["/opt/empty_a"])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(binding).To(gomega.Equal(originalBinding{Source: "src-a", Path: "testdata/a"}))
	})

	ginkgo.It("never attributes a file the scoped matches do not cover", func() {
		before := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes", "/opt/unscoped": "unscoped-bytes"})
		after := fixtureIndex(map[string]string{"/opt/tool": "tool-bytes", "/opt/unscoped": "unscoped-bytes", "/opt/copy": "unscoped-bytes"})

		carried, err := carryOriginalMatches(before, originalMatches{"/opt/tool": {{Source: "src-tool", Path: "bin/tool"}}}, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(slices.Sorted(maps.Keys(carried))).To(gomega.Equal([]string{"/opt/tool"}))
	})

	ginkgo.It("offers same-byte originals as alternatives that no helper resolves", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes", "/b/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/moved/lib": "shared-bytes"})
		matches := originalMatches{
			"/b/lib": {{Source: "src-b", Path: "lib/lib"}},
			"/a/lib": {{Source: "src-a", Path: "lib/lib"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried["/moved/lib"]).To(gomega.Equal([]originalBinding{
			{Source: "src-a", Path: "lib/lib"},
			{Source: "src-b", Path: "lib/lib"},
		}))

		_, err = uniqueOriginalBinding(carried["/moved/lib"])
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("keeps an unchanged path on its own bindings while a same-byte path exists", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes", "/b/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/a/lib": "shared-bytes", "/b/lib": "other-bytes"})
		matches := originalMatches{
			"/a/lib": {{Source: "src-a", Path: "lib/lib"}},
			"/b/lib": {{Source: "src-b", Path: "lib/lib"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried).To(gomega.Equal(originalMatches{"/a/lib": {{Source: "src-a", Path: "lib/lib"}}}))

		binding, err := uniqueOriginalBinding(carried["/a/lib"])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(binding).To(gomega.Equal(originalBinding{Source: "src-a", Path: "lib/lib"}))
	})

	ginkgo.It("retains alternatives as alternatives on an unchanged path", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		matches := originalMatches{"/a/lib": {{Source: "src-b", Path: "lib/lib"}, {Source: "src-a", Path: "lib/lib"}}}

		carried, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried["/a/lib"]).To(gomega.Equal([]originalBinding{
			{Source: "src-a", Path: "lib/lib"},
			{Source: "src-b", Path: "lib/lib"},
		}))

		_, err = uniqueOriginalBinding(carried["/a/lib"])
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("treats repeated identical bindings as one original", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes", "/b/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/moved/lib": "shared-bytes"})
		matches := originalMatches{
			"/a/lib": {{Source: "src-a", Path: "lib/lib"}, {Source: "src-a", Path: "lib/lib"}},
			"/b/lib": {{Source: "src-a", Path: "lib/lib"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		binding, err := uniqueOriginalBinding(carried["/moved/lib"])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(binding).To(gomega.Equal(originalBinding{Source: "src-a", Path: "lib/lib"}))
	})

	ginkgo.It("orders alternatives the same way whatever order they arrive in", func() {
		before := fixtureIndex(map[string]string{"/a": "shared-bytes", "/b": "shared-bytes", "/c": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/moved": "shared-bytes"})
		expected := []originalBinding{
			{Source: "src-a", Path: "one"},
			{Source: "src-a", Path: "two"},
			{Source: "src-b", Path: "one"},
		}

		for _, matches := range []originalMatches{
			{"/a": {{Source: "src-b", Path: "one"}}, "/b": {{Source: "src-a", Path: "two"}}, "/c": {{Source: "src-a", Path: "one"}}},
			{"/a": {{Source: "src-a", Path: "one"}}, "/b": {{Source: "src-b", Path: "one"}}, "/c": {{Source: "src-a", Path: "two"}}},
		} {
			carried, err := carryOriginalMatches(before, matches, after)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(carried["/moved"]).To(gomega.Equal(expected))
		}
	})

	ginkgo.It("rejects matches that are not grounded in the before snapshot", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})

		for _, matches := range []originalMatches{
			{"/a/lib": {{Source: "src-a", Path: "lib/lib"}}, "/absent": {{Source: "src-x", Path: "lib/x"}}},
			{"/a/lib": nil},
			{"/a/lib": {{Source: "", Path: "lib/lib"}}},
			{"/a/lib": {{Source: "src-a", Path: ""}}},
		} {
			carried, err := carryOriginalMatches(before, matches, after)
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(carried).To(gomega.BeNil())
		}
	})

	ginkgo.It("reports no data when a snapshot is missing or incomplete", func() {
		index := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		matches := originalMatches{"/a/lib": {{Source: "src-a", Path: "lib/lib"}}}
		incomplete := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		incomplete.Incomplete = true

		for _, pair := range [][2]*shippedscope.FileIndex{{nil, index}, {index, nil}, {incomplete, index}, {index, incomplete}} {
			carried, err := carryOriginalMatches(pair[0], matches, pair[1])
			gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
			gomega.Expect(carried).To(gomega.BeNil())
		}
	})

	ginkgo.It("leaves the caller's matches untouched", func() {
		before := fixtureIndex(map[string]string{"/a/lib": "shared-bytes"})
		after := fixtureIndex(map[string]string{"/a/lib": "shared-bytes", "/copy/lib": "shared-bytes"})
		bindings := []originalBinding{{Source: "src-b", Path: "lib/b"}, {Source: "src-a", Path: "lib/a"}}
		matches := originalMatches{"/a/lib": bindings}

		_, err := carryOriginalMatches(before, matches, after)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(bindings).To(gomega.Equal([]originalBinding{{Source: "src-b", Path: "lib/b"}, {Source: "src-a", Path: "lib/a"}}))
		gomega.Expect(matches).To(gomega.Equal(originalMatches{"/a/lib": bindings}))

		_, err = uniqueOriginalBinding(bindings)
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(bindings[0]).To(gomega.Equal(originalBinding{Source: "src-b", Path: "lib/b"}))
	})

	ginkgo.It("reports no data for an empty set of alternatives", func() {
		_, err := uniqueOriginalBinding(nil)
		gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
	})

	ginkgo.It("reports no data for a lone binding that names no usable original", func() {
		for _, binding := range []originalBinding{{Path: "lib/lib"}, {Source: "src-a"}, {}} {
			resolved, err := uniqueOriginalBinding([]originalBinding{binding})
			gomega.Expect(err).To(gomega.MatchError(gomega.HavePrefix("no-data")))
			gomega.Expect(resolved).To(gomega.Equal(originalBinding{}))
		}
	})

	// An empty file holds its own evidence where it stands and gives none away. Its
	// bytes are every empty file's bytes: letting them speak would hand each of these
	// three to all of them at once, and hand the same to every empty file the build
	// happens to write.
	ginkgo.It("keeps an empty file's own evidence and lets its bytes name nothing", func() {
		before := fixtureIndex(map[string]string{"/a/empty": "", "/b/empty": "", "/kept/empty": ""})
		after := fixtureIndex(map[string]string{"/kept/empty": "", "/renamed/empty": ""})
		matches := originalMatches{
			"/a/empty":    {{Source: "src-a", Path: "share/empty"}},
			"/b/empty":    {{Source: "src-b", Path: "share/empty"}},
			"/kept/empty": {{Source: "src-kept", Path: "share/empty"}},
		}

		carried, err := carryOriginalMatches(before, matches, after)

		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(carried).To(gomega.Equal(originalMatches{
			"/kept/empty": {{Source: "src-kept", Path: "share/empty"}},
		}), "the file that stayed keeps what was proven of it, and the one that appeared is attributed to nothing")
	})
})
