package managedinput

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GoModCacheDir", func() {
	DescribeTable("resolves the module cache the way the go tool does inside the image",
		func(env []string, expected string) {
			Expect(GoModCacheDir(env)).To(Equal(expected))
		},
		Entry("official golang image sets GOPATH", []string{"PATH=/usr/bin", "GOPATH=/go"}, "/go/pkg/mod"),
		Entry("GOMODCACHE wins over GOPATH", []string{"GOPATH=/go", "GOMODCACHE=/cache/mod"}, "/cache/mod"),
		Entry("first GOPATH element holds the cache", []string{"GOPATH=/first:/second"}, "/first/pkg/mod"),
		Entry("no GOPATH falls back to $HOME/go", []string{"HOME=/home/build"}, "/home/build/go/pkg/mod"),
		Entry("no GOPATH and no HOME falls back to /root/go", []string{"PATH=/usr/bin"}, "/root/go/pkg/mod"),
		Entry("empty environment", nil, "/root/go/pkg/mod"),
		Entry("malformed entries are ignored", []string{"NOEQUALS", "GOPATH=/go"}, "/go/pkg/mod"),
	)
})

var _ = Describe("GoModCacheModuleDirs", func() {
	DescribeTable("maps go.sum entries to module cache directories",
		func(goSum string, expected []string) {
			dirs, err := GoModCacheModuleDirs([]byte(goSum))
			Expect(err).To(Succeed())
			Expect(dirs).To(Equal(expected))
		},
		Entry("h1 and /go.mod lines of one module collapse into one directory",
			"github.com/samber/lo v1.47.0 h1:abc=\ngithub.com/samber/lo v1.47.0/go.mod h1:def=\n",
			[]string{"github.com/samber/lo@v1.47.0"},
		),
		Entry("upper-case letters in the module path are escaped as the go tool does",
			"github.com/Azure/go-autorest v14.2.0+incompatible h1:x=\n",
			[]string{"github.com/!azure/go-autorest@v14.2.0+incompatible"},
		),
		Entry("pseudo-versions and major suffixes are kept verbatim",
			"golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 h1:x=\ngithub.com/foo/bar/v2 v2.1.0 h1:y=\n",
			[]string{"golang.org/x/sys@v0.0.0-20220715151400-c0bba94af5f8", "github.com/foo/bar/v2@v2.1.0"},
		),
		Entry("order of first appearance is preserved",
			"b.example/m v1.0.0 h1:x=\na.example/m v1.0.0 h1:y=\nb.example/m v1.0.0/go.mod h1:z=\n",
			[]string{"b.example/m@v1.0.0", "a.example/m@v1.0.0"},
		),
		Entry("blank and short lines are ignored",
			"\n\ngithub.com/samber/lo v1.47.0 h1:abc=\njunk\n",
			[]string{"github.com/samber/lo@v1.47.0"},
		),
		Entry("empty go.sum yields no modules", "", nil),
	)

	It("rejects a module path the go tool would reject", func() {
		_, err := GoModCacheModuleDirs([]byte("bad path with spaces v1.0.0 h1:x=\n"))
		Expect(err).To(HaveOccurred())
	})
})
