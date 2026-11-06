package gomod

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
)

var _ = Describe("DropUnrequiredLocalReplaces", func() {
	goMod := `module go.etcd.io/etcd/server/v3

go 1.24

require (
	go.etcd.io/etcd/api/v3 v3.6.13
	github.com/spf13/cobra v1.9.1
)

replace (
	go.etcd.io/etcd/api/v3 => ../api
	go.etcd.io/tests/v3 => ./FORBIDDEN_DEPENDENCY
	go.etcd.io/etcd => ./FORBIDDEN_DEPENDENCY
	github.com/old/lib => github.com/new/lib v1.2.0
)
`

	component := func(name, version string) cdx.Component {
		purl := "pkg:golang/" + name
		if version != "" {
			purl += "@" + version
		}
		return cdx.Component{Type: cdx.ComponentTypeLibrary, Name: name, Version: version, PackageURL: purl, BOMRef: purl}
	}

	It("drops the guard replaces that no require backs, and keeps everything else", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{
			component("go.etcd.io/tests/v3", ""),
			component("go.etcd.io/etcd", ""),
			component("go.etcd.io/etcd/api/v3", ""),
			component("github.com/spf13/cobra", "v1.9.1"),
			component("github.com/new/lib", "v1.2.0"),
		}}

		Expect(DropUnrequiredLocalReplaces(bom, []byte(goMod))).To(Succeed())

		names := lo.Map(*bom.Components, func(c cdx.Component, _ int) string { return c.Name })
		Expect(names).To(ConsistOf("go.etcd.io/etcd/api/v3", "github.com/spf13/cobra", "github.com/new/lib"))
	})

	It("leaves a required local replace alone even when its version is unknown", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{component("go.etcd.io/etcd/api/v3", "")}}

		Expect(DropUnrequiredLocalReplaces(bom, []byte(goMod))).To(Succeed())

		Expect(*bom.Components).To(HaveLen(1))
	})

	It("does not touch a component of another ecosystem with the same name", func() {
		bom := &cdx.BOM{Components: &[]cdx.Component{{Type: cdx.ComponentTypeLibrary, Name: "go.etcd.io/tests/v3", PackageURL: "pkg:generic/go.etcd.io/tests/v3", BOMRef: "x"}}}

		Expect(DropUnrequiredLocalReplaces(bom, []byte(goMod))).To(Succeed())

		Expect(*bom.Components).To(HaveLen(1))
	})

	It("fails on an unparsable go.mod", func() {
		Expect(DropUnrequiredLocalReplaces(&cdx.BOM{}, []byte("module"))).NotTo(Succeed())
	})
})
