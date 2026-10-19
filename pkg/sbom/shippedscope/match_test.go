package shippedscope

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Match, binary-backed components", func() {
	goBinaryNaming := func(modules ...string) BinaryClassification {
		return BinaryClassification{Go: VerdictNames, Modules: modules, Rust: VerdictNone}
	}

	It("holds the modules a produced binary names and drops the rest", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "gopkg.in/yaml.v3"},
			{Ecosystem: EcosystemGo, Name: "github.com/spf13/cobra"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{goBinaryNaming("gopkg.in/yaml.v3")}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonBinary}))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNotLinked}))
	})

	It("lets one binary hold several modules at once", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
			{Ecosystem: EcosystemGo, Name: "b"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{goBinaryNaming("a", "b")}}, emptyIndex())

		Expect(decisions).To(HaveEach(Equal(Decision{Shipped: true, Reason: ReasonBinary})))
	})

	It("holds every module when any produced binary could carry modules but names none", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			goBinaryNaming("b"),
			{Go: VerdictUnknown, Rust: VerdictNone},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonFailOpen}))
	})

	It("reports a module a binary names as held by that binary, even when another binary is unreadable", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
			{Ecosystem: EcosystemGo, Name: "b"},
			{Ecosystem: EcosystemRust, Name: "serde", Version: "1"},
			{Ecosystem: EcosystemRust, Name: "tokio", Version: "1"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{Go: VerdictNames, Modules: []string{"a"}, Rust: VerdictNames, Crates: []Crate{{Name: "serde", Version: "1"}}},
			{Go: VerdictUnknown, Rust: VerdictUnknown},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonBinary}))
		Expect(decisions[1]).To(Equal(Decision{Shipped: true, Reason: ReasonFailOpen}))
		Expect(decisions[2]).To(Equal(Decision{Shipped: true, Reason: ReasonBinary}))
		Expect(decisions[3]).To(Equal(Decision{Shipped: true, Reason: ReasonFailOpen}))
	})

	It("lets a test binary speak for nobody, whatever it names", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "github.com/stretchr/testify"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{TestBinary: true, Go: VerdictNames, Modules: []string{"github.com/stretchr/testify"}},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Reason: ReasonNotLinked}))
	})

	It("does not let a test binary that cannot be read fail everything open", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{TestBinary: true, Go: VerdictUnknown, Rust: VerdictUnknown},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Reason: ReasonNotLinked}))
	})

	It("drops every module when the build is known to have produced no binary", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
		}, ProducedBinaries{Known: true}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Reason: ReasonNotLinked}))
	})

	It("holds every module when the produced set could not be established at all", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
			{Ecosystem: EcosystemRust, Name: "serde", Version: "1.0.210"},
		}, ProducedBinaries{}, emptyIndex())

		Expect(decisions).To(HaveEach(Equal(Decision{Shipped: true, Reason: ReasonNoData})))
	})

	It("matches a crate by name and version, and a module by path alone", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemRust, Name: "serde", Version: "1.0.210"},
			{Ecosystem: EcosystemRust, Name: "serde", Version: "1.0.100"},
			{Ecosystem: EcosystemGo, Name: "a", Version: "v9.9.9"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{Go: VerdictNames, Modules: []string{"a"}, Rust: VerdictNames, Crates: []Crate{{Name: "serde", Version: "1.0.210"}}},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonBinary}))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNotLinked}))
		Expect(decisions[2]).To(Equal(Decision{Shipped: true, Reason: ReasonBinary}))
	})

	It("reads Go and Rust evidence independently of each other", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemGo, Name: "a"},
			{Ecosystem: EcosystemRust, Name: "serde", Version: "1"},
		}, ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{Go: VerdictNames, Modules: []string{"b"}, Rust: VerdictUnknown},
		}}, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Reason: ReasonNotLinked}))
		Expect(decisions[1]).To(Equal(Decision{Shipped: true, Reason: ReasonFailOpen}))
	})
})

var _ = Describe("Match, file-backed components", func() {
	noBinaries := ProducedBinaries{Known: true}

	It("holds a component whose own file is in the image byte for byte", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/bin/jq": {Digest: "sha256:jq", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "jq", Version: "1.6", Occurrences: []Occurrence{{Path: "/usr/bin/jq", Digest: "sha256:jq"}}},
			{Ecosystem: EcosystemOSPM, Name: "gcc-12", Version: "12", Occurrences: []Occurrence{{Path: "/usr/bin/gcc", Digest: "sha256:gcc"}}},
		}, noBinaries, index)

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonContent, Checked: 1, Matched: []string{"/bin/jq"}}))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch, Checked: 1}))
	})

	It("keeps a component nothing is known about, and drops one whose files were looked for and not found", func(ctx SpecContext) {
		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "libfoo", Version: "1"},
			{Ecosystem: EcosystemOSPM, Name: "libbar", Version: "1", Occurrences: []Occurrence{}},
		}, noBinaries, emptyIndex())

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonNoData}))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch}))
	})

	It("does not take a zero-size file as evidence", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/x/__init__.py": {Digest: "sha256:empty", Size: 0}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemPython, Name: "x", Version: "1", Occurrences: []Occurrence{{Path: "/site/x/__init__.py", Digest: "sha256:empty"}}},
		}, noBinaries, index)

		Expect(decisions[0].Shipped).To(BeFalse())
	})

	It("credits a shared file to the owner that proved itself by a file of its own", func(ctx SpecContext) {
		index := indexOf(map[string]File{
			"/usr/bin/c_rehash":    {Digest: "sha256:rehash", Size: 10},
			"/usr/lib/libssl.so.3": {Digest: "sha256:ssl-new", Size: 10},
		})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "openssl", Version: "3.0.13", Occurrences: []Occurrence{
				{Path: "/usr/bin/c_rehash", Digest: "sha256:rehash"},
				{Path: "/usr/lib/libssl.so.3", Digest: "sha256:ssl-new"},
			}},
			{Ecosystem: EcosystemOSPM, Name: "openssl", Version: "3.0.11", Occurrences: []Occurrence{
				{Path: "/usr/bin/c_rehash", Digest: "sha256:rehash"},
				{Path: "/usr/lib/libssl.so.3", Digest: "sha256:ssl-old"},
			}},
		}, noBinaries, index)

		// The proven owner is credited with the shared file as well: the rule decided it is
		// its, and the next image in the chain may import only that file.
		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonContent, Checked: 2, Matched: []string{"/usr/bin/c_rehash", "/usr/lib/libssl.so.3"}}))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch, Checked: 2}))
	})

	It("treats two files with the same bytes at two paths as two files, each its owner's", func(ctx SpecContext) {
		index := indexOf(map[string]File{
			"/x/f": {Digest: "sha256:d", Size: 10},
			"/y/f": {Digest: "sha256:d", Size: 10},
			"/y/g": {Digest: "sha256:g", Size: 10},
		})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemPython, Name: "x", Version: "1", Occurrences: []Occurrence{{Path: "/x/f", Digest: "sha256:d"}}},
			{Ecosystem: EcosystemPython, Name: "y", Version: "1", Occurrences: []Occurrence{{Path: "/y/f", Digest: "sha256:d"}, {Path: "/y/g", Digest: "sha256:g"}}},
		}, noBinaries, index)

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonContent, Checked: 1, Matched: []string{"/x/f"}}))
		Expect(decisions[1]).To(Equal(Decision{Shipped: true, Reason: ReasonContent, Checked: 2, Matched: []string{"/y/f", "/y/g"}}))
	})

	It("lets every owner of the bytes contest a file nobody declares at its image path", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/bin/jq": {Digest: "sha256:jq", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "jq", Version: "1.6", Occurrences: []Occurrence{{Path: "/usr/bin/jq", Digest: "sha256:jq"}}},
			{Ecosystem: EcosystemOSPM, Name: "jq-static", Version: "1.6", Occurrences: []Occurrence{{Path: "/opt/jq/jq", Digest: "sha256:jq"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(Equal(Decision{Shipped: true, Reason: ReasonContentShared, Checked: 1, Matched: []string{"/bin/jq"}})))
	})

	It("credits a content-shared component with every shared file it has in the image", func(ctx SpecContext) {
		index := indexOf(map[string]File{
			"/s/a": {Digest: "sha256:a", Size: 10},
			"/s/b": {Digest: "sha256:b", Size: 10},
		})
		both := []Occurrence{{Path: "/s/a", Digest: "sha256:a"}, {Path: "/s/b", Digest: "sha256:b"}}

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "foo", Version: "1", Occurrences: both},
			{Ecosystem: EcosystemOSPM, Name: "foo-data", Version: "1", Occurrences: both},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(Equal(Decision{Shipped: true, Reason: ReasonContentShared, Checked: 2, Matched: []string{"/s/a", "/s/b"}})))
	})

	It("drops every unproven owner of a shared file once one owner is proven, however many there are", func(ctx SpecContext) {
		index := indexOf(map[string]File{
			"/usr/bin/c_rehash":    {Digest: "sha256:rehash", Size: 10},
			"/usr/lib/libssl.so.3": {Digest: "sha256:ssl-13", Size: 10},
		})
		rehash := Occurrence{Path: "/usr/bin/c_rehash", Digest: "sha256:rehash"}

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "openssl", Version: "3.0.11", Occurrences: []Occurrence{rehash, {Path: "/usr/lib/libssl.so.3", Digest: "sha256:ssl-11"}}},
			{Ecosystem: EcosystemOSPM, Name: "openssl", Version: "3.0.12", Occurrences: []Occurrence{rehash, {Path: "/usr/lib/libssl.so.3", Digest: "sha256:ssl-12"}}},
			{Ecosystem: EcosystemOSPM, Name: "openssl", Version: "3.0.13", Occurrences: []Occurrence{rehash, {Path: "/usr/lib/libssl.so.3", Digest: "sha256:ssl-13"}}},
		}, noBinaries, index)

		Expect(decisions[0].Shipped).To(BeFalse())
		Expect(decisions[1].Shipped).To(BeFalse())
		Expect(decisions[2].Reason).To(Equal(ReasonContent))
	})

	It("does not let a copy of a package count as a proven co-owner against itself", func(ctx SpecContext) {
		// Copy 1 of debug is proven by a file of its own. Copy 2 and `other` both declare
		// /shared/f. Copy 2 is the same owner as copy 1, so it must not read copy 1's
		// proof as a co-owner's and drop itself — while `other`, sharing the file with
		// that proven owner, does drop.
		index := indexOf(map[string]File{
			"/a/node_modules/debug/index.js": {Digest: "sha256:debug", Size: 10},
			"/shared/f":                      {Digest: "sha256:f", Size: 10},
		})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemJavaScript, Name: "debug", Version: "2.6.9", Occurrences: []Occurrence{{Path: "/a/node_modules/debug/index.js", Digest: "sha256:debug"}}},
			{Ecosystem: EcosystemJavaScript, Name: "debug", Version: "2.6.9", Occurrences: []Occurrence{{Path: "/shared/f", Digest: "sha256:f"}}},
			{Ecosystem: EcosystemJavaScript, Name: "other", Version: "1", Occurrences: []Occurrence{{Path: "/shared/f", Digest: "sha256:f"}}},
		}, noBinaries, index)

		Expect(decisions[0].Reason).To(Equal(ReasonContent))
		Expect(decisions[1].Reason).To(Equal(ReasonContentShared))
		Expect(decisions[2].Reason).To(Equal(ReasonNoMatch))
	})

	It("holds a component made only of symlinks by their paths, and drops it when they are gone", func(ctx SpecContext) {
		present := &FileIndex{Files: map[string]File{}, Symlinks: map[string]string{"/usr/bin/python": "python3"}}
		absent := emptyIndex()
		component := []Component{
			{Ecosystem: EcosystemOSPM, Name: "python-is-python3", Version: "3", Occurrences: []Occurrence{{Path: "/usr/bin/python", Symlink: true}}},
		}

		Expect(Match(ctx, component, noBinaries, present)[0]).To(Equal(Decision{Shipped: true, Reason: ReasonPath, Matched: []string{"/usr/bin/python"}}))
		Expect(Match(ctx, component, noBinaries, absent)[0]).To(Equal(Decision{Reason: ReasonNoMatch}))
	})

	It("holds both owners of a shared file when neither proved itself otherwise", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/usr/share/x/data": {Digest: "sha256:data", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "foo", Version: "1", Occurrences: []Occurrence{{Path: "/usr/share/x/data", Digest: "sha256:data"}}},
			{Ecosystem: EcosystemOSPM, Name: "foo-data", Version: "1", Occurrences: []Occurrence{{Path: "/usr/share/x/data", Digest: "sha256:data"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(Equal(Decision{Shipped: true, Reason: ReasonContentShared, Checked: 1, Matched: []string{"/usr/share/x/data"}})))
	})

	It("counts ownership within an ecosystem, so a deb shipping an npm tree does not block the npm packages", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/usr/share/nodejs/lodash/lodash.js": {Digest: "sha256:lodash", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "node-lodash", Version: "4", Occurrences: []Occurrence{{Path: "/usr/share/nodejs/lodash/lodash.js", Digest: "sha256:lodash"}}},
			{Ecosystem: EcosystemJavaScript, Name: "lodash", Version: "4.17.21", Occurrences: []Occurrence{{Path: "/usr/share/nodejs/lodash/lodash.js", Digest: "sha256:lodash"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(HaveField("Reason", ReasonContent)))
	})

	It("counts ownership by package version, so identical copies of one package are one owner", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/app/node_modules/debug/index.js": {Digest: "sha256:debug", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemJavaScript, Name: "debug", Version: "2.6.9", Occurrences: []Occurrence{{Path: "/app/node_modules/debug/index.js", Digest: "sha256:debug"}}},
			{Ecosystem: EcosystemJavaScript, Name: "debug", Version: "2.6.9", Occurrences: []Occurrence{{Path: "/app/node_modules/x/node_modules/debug/index.js", Digest: "sha256:debug"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(HaveField("Reason", ReasonContent)))
	})

	It("holds a component whose file was rewritten in place, by its path", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/etc/ssl/certs/ca-certificates.crt": {Digest: "sha256:regenerated", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "ca-certificates", Version: "2024", Occurrences: []Occurrence{{Path: "/etc/ssl/certs/ca-certificates.crt", Digest: "sha256:as-installed"}}},
		}, noBinaries, index)

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonPath, Checked: 1, Matched: []string{"/etc/ssl/certs/ca-certificates.crt"}}))
	})

	It("does not let a path explained by a proven component hold a stale one", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/usr/lib/libc.so.6": {Digest: "sha256:libc-new", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "libc6", Version: "2.36", Occurrences: []Occurrence{{Path: "/usr/lib/libc.so.6", Digest: "sha256:libc-new"}}},
			{Ecosystem: EcosystemOSPM, Name: "libc6", Version: "2.31", Occurrences: []Occurrence{{Path: "/usr/lib/libc.so.6", Digest: "sha256:libc-old"}}},
		}, noBinaries, index)

		Expect(decisions[0].Reason).To(Equal(ReasonContent))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch, Checked: 1}))
	})

	It("does not let a proven component's symlink hold a stale version by path", func(ctx SpecContext) {
		index := &FileIndex{
			Files:    map[string]File{"/usr/lib/libz.so.1.3": {Digest: "sha256:z-new", Size: 10}},
			Symlinks: map[string]string{"/usr/lib/libz.so.1": "libz.so.1.3"},
		}

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "zlib1g", Version: "1.3", Occurrences: []Occurrence{
				{Path: "/usr/lib/libz.so.1.3", Digest: "sha256:z-new"},
				{Path: "/usr/lib/libz.so.1", Symlink: true},
			}},
			{Ecosystem: EcosystemOSPM, Name: "zlib1g", Version: "1.2", Occurrences: []Occurrence{
				{Path: "/usr/lib/libz.so.1.2", Digest: "sha256:z-old"},
				{Path: "/usr/lib/libz.so.1", Symlink: true},
			}},
		}, noBinaries, index)

		Expect(decisions[0].Reason).To(Equal(ReasonContent))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch, Checked: 1}))
	})

	It("holds a relocated and rewritten file by its unique name", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/opt/tool/bin/jq": {Digest: "sha256:jq-stripped", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "jq", Version: "1.6", Occurrences: []Occurrence{{Path: "/usr/bin/jq", Digest: "sha256:jq"}}},
		}, noBinaries, index)

		Expect(decisions[0]).To(Equal(Decision{Shipped: true, Reason: ReasonName, Checked: 1, Matched: []string{"/opt/tool/bin/jq"}}))
	})

	It("does not match by a name every package carries, nor by one two components share", func(ctx SpecContext) {
		index := indexOf(map[string]File{
			"/opt/a/LICENSE":  {Digest: "sha256:lic", Size: 10},
			"/opt/a/utils.py": {Digest: "sha256:u", Size: 10},
		})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemPython, Name: "a", Version: "1", Occurrences: []Occurrence{{Path: "/site/a/LICENSE", Digest: "sha256:lic-a"}, {Path: "/site/a/utils.py", Digest: "sha256:ua"}}},
			{Ecosystem: EcosystemPython, Name: "b", Version: "1", Occurrences: []Occurrence{{Path: "/site/b/utils.py", Digest: "sha256:ub"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveEach(HaveField("Shipped", BeFalse())))
	})

	It("looks for a path or a name only among files no proven component explains", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/usr/bin/tool": {Digest: "sha256:tool-new", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "tool", Version: "2", Occurrences: []Occurrence{{Path: "/usr/bin/tool", Digest: "sha256:tool-new"}}},
			{Ecosystem: EcosystemOSPM, Name: "tool-legacy", Version: "1", Occurrences: []Occurrence{{Path: "/opt/legacy/tool", Digest: "sha256:tool-old"}}},
		}, noBinaries, index)

		Expect(decisions[0].Reason).To(Equal(ReasonContent))
		Expect(decisions[1]).To(Equal(Decision{Reason: ReasonNoMatch, Checked: 1}))
	})

	It("returns decisions in the order of components", func(ctx SpecContext) {
		index := indexOf(map[string]File{"/bin/jq": {Digest: "sha256:jq", Size: 10}})

		decisions := Match(ctx, []Component{
			{Ecosystem: EcosystemOSPM, Name: "gcc", Version: "12", Occurrences: []Occurrence{{Path: "/usr/bin/gcc", Digest: "sha256:gcc"}}},
			{Ecosystem: EcosystemGo, Name: "a"},
			{Ecosystem: EcosystemOSPM, Name: "jq", Version: "1.6", Occurrences: []Occurrence{{Path: "/usr/bin/jq", Digest: "sha256:jq"}}},
		}, noBinaries, index)

		Expect(decisions).To(HaveLen(3))
		Expect(decisions[0].Shipped).To(BeFalse())
		Expect(decisions[1].Shipped).To(BeFalse())
		Expect(decisions[2].Shipped).To(BeTrue())
	})
})

// The end-to-end stand of the concept (bench-e2e/expected.json), as the rule sees it: a
// builder's components with the files the builder gave them, matched against what the
// final image took.
var _ = Describe("Match, the concept's end-to-end stand", func() {
	It("reproduces the expected decisions", func(ctx SpecContext) {
		final := indexOf(map[string]File{
			"/app":                       {Digest: "sha256:app", Size: 10},
			"/app/py/requests/api.py":    {Digest: "sha256:req-api", Size: 10},
			"/app/js/lodash/lodash.js":   {Digest: "sha256:lodash", Size: 10},
			"/bin/jq":                    {Digest: "sha256:jq", Size: 10},
			"/lib/x86_64/libz.so.1.2.13": {Digest: "sha256:libz", Size: 10},
			"/lib/x86_64/libc.so.6":      {Digest: "sha256:libc", Size: 10},
		})

		produced := ProducedBinaries{Known: true, Binaries: []BinaryClassification{
			{Go: VerdictNames, Modules: []string{"gopkg.in/yaml.v3"}, Rust: VerdictNone},
		}}

		components := []Component{
			{Ecosystem: EcosystemGo, Name: "gopkg.in/yaml.v3"},
			{Ecosystem: EcosystemGo, Name: "github.com/spf13/cobra"},
			{Ecosystem: EcosystemGo, Name: "github.com/spf13/pflag"},
			{Ecosystem: EcosystemPython, Name: "requests", Version: "2.32", Occurrences: []Occurrence{{Path: "/venv/lib/site-packages/requests/api.py", Digest: "sha256:req-api"}}},
			{Ecosystem: EcosystemPython, Name: "certifi", Version: "2024", Occurrences: []Occurrence{{Path: "/venv/lib/site-packages/certifi/core.py", Digest: "sha256:certifi"}}},
			{Ecosystem: EcosystemPython, Name: "idna", Version: "3", Occurrences: []Occurrence{{Path: "/venv/lib/site-packages/idna/core.py", Digest: "sha256:idna"}}},
			{Ecosystem: EcosystemPython, Name: "pytest", Version: "8", Occurrences: []Occurrence{{Path: "/venv/lib/site-packages/pytest/main.py", Digest: "sha256:pytest"}}},
			{Ecosystem: EcosystemJavaScript, Name: "lodash", Version: "4.17.21", Occurrences: []Occurrence{{Path: "/src/node_modules/lodash/lodash.js", Digest: "sha256:lodash"}}},
			{Ecosystem: EcosystemJavaScript, Name: "jest", Version: "29", Occurrences: []Occurrence{{Path: "/src/node_modules/jest/bin/jest.js", Digest: "sha256:jest"}}},
			{Ecosystem: EcosystemJavaScript, Name: "@babel/cli", Version: "7", Occurrences: []Occurrence{{Path: "/usr/share/nodejs/@babel/cli/bin/babel.js", Digest: "sha256:babel"}}},
			{Ecosystem: EcosystemOSPM, Name: "jq", Version: "1.6", Occurrences: []Occurrence{{Path: "/usr/bin/jq", Digest: "sha256:jq"}}},
			{Ecosystem: EcosystemOSPM, Name: "libpcre3", Version: "8.39", Occurrences: []Occurrence{{Path: "/lib/x86_64/libpcre.so.3.13", Digest: "sha256:pcre-builder"}}},
			{Ecosystem: EcosystemOSPM, Name: "zlib1g", Version: "1.2.13", Occurrences: []Occurrence{{Path: "/lib/x86_64/libz.so.1.2.13", Digest: "sha256:libz"}}},
			{Ecosystem: EcosystemOSPM, Name: "libc6", Version: "2.36", Occurrences: []Occurrence{{Path: "/lib/x86_64/libc.so.6", Digest: "sha256:libc"}}},
			{Ecosystem: EcosystemOSPM, Name: "gcc-12", Version: "12", Occurrences: []Occurrence{{Path: "/usr/bin/gcc-12", Digest: "sha256:gcc"}}},
			{Ecosystem: EcosystemOSPM, Name: "python3-pip", Version: "23", Occurrences: []Occurrence{{Path: "/usr/bin/pip3", Digest: "sha256:pip"}}},
			{Ecosystem: EcosystemOSPM, Name: "npm", Version: "9", Occurrences: []Occurrence{{Path: "/usr/bin/npm", Digest: "sha256:npm"}}},
		}

		decisions := Match(ctx, components, produced, final)

		reasons := map[string]Reason{}
		for i, component := range components {
			reasons[string(component.Ecosystem)+":"+component.Name] = decisions[i].Reason
		}
		Expect(reasons).To(Equal(map[string]Reason{
			"go:gopkg.in/yaml.v3":       ReasonBinary,
			"go:github.com/spf13/cobra": ReasonNotLinked,
			"go:github.com/spf13/pflag": ReasonNotLinked,
			"python:requests":           ReasonContent,
			"python:certifi":            ReasonNoMatch,
			"python:idna":               ReasonNoMatch,
			"python:pytest":             ReasonNoMatch,
			"javascript:lodash":         ReasonContent,
			"javascript:jest":           ReasonNoMatch,
			"javascript:@babel/cli":     ReasonNoMatch,
			"os-pm:jq":                  ReasonContent,
			"os-pm:libpcre3":            ReasonNoMatch,
			"os-pm:zlib1g":              ReasonContent,
			"os-pm:libc6":               ReasonContent,
			"os-pm:gcc-12":              ReasonNoMatch,
			"os-pm:python3-pip":         ReasonNoMatch,
			"os-pm:npm":                 ReasonNoMatch,
		}))
	})
})

func emptyIndex() *FileIndex {
	return &FileIndex{Files: map[string]File{}, Symlinks: map[string]string{}}
}

func indexOf(files map[string]File) *FileIndex {
	return &FileIndex{Files: files, Symlinks: map[string]string{}}
}
