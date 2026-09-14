package ispras

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

var _ = Describe("aggregateGOST", func() {
	withGOST := func(name string, attack, security gost.GostValue, children ...cdx.Component) cdx.Component {
		comp := cdx.Component{Name: name}
		gost.SetComponent(&comp, gost.Config{AttackSurface: attack, SecurityFunction: security})
		if len(children) > 0 {
			comp.Components = &children
		}
		return comp
	}

	DescribeTable("takes the maximum over all descendants",
		func(components []cdx.Component, expected GOSTValues) {
			Expect(aggregateGOST(components)).To(Equal(expected))
		},
		Entry("empty", nil, GOSTValues{}),
		Entry("flat list",
			[]cdx.Component{
				withGOST("a", gost.GostValueNo, gost.GostValueIndirect),
				withGOST("b", gost.GostValueIndirect, gost.GostValueNo),
			},
			GOSTValues{AttackSurface: gost.GostValueIndirect, SecurityFunction: gost.GostValueIndirect}),
		Entry("higher value only in a grandchild",
			[]cdx.Component{
				withGOST("parent", gost.GostValueNo, gost.GostValueNo,
					withGOST("child", gost.GostValueIndirect, gost.GostValueNo,
						withGOST("grandchild", gost.GostValueYes, gost.GostValueYes),
					),
				),
			},
			GOSTValues{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueYes}),
		Entry("fields are aggregated independently",
			[]cdx.Component{
				withGOST("parent", gost.GostValueYes, gost.GostValueNo,
					withGOST("child", gost.GostValueNo, gost.GostValueIndirect),
				),
			},
			GOSTValues{AttackSurface: gost.GostValueYes, SecurityFunction: gost.GostValueIndirect}),
	)
})
