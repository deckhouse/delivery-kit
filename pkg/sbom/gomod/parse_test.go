package gomod

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

type infoAssert func(*GoModInfo)

var _ = Describe("Go mod parser", func() {
	Describe("ParseLocalReplaces", func() {
		DescribeTable(
			"parses module and local replaces",
			func(goMod string, expectedErrMatcher types.GomegaMatcher, expectedInfo infoAssert) {
				info, err := ParseLocalReplaces([]byte(goMod))
				Expect(err).To(expectedErrMatcher)
				if err != nil {
					return
				}

				Expect(info).ToNot(BeNil())
				if expectedInfo != nil {
					expectedInfo(info)
				}
			},

			Entry(
				"invalid go.mod",
				"module",
				MatchError(ContainSubstring("parse go.mod")),
				nil,
			),
			Entry(
				"no replace directives",
				"module example.com/app\n\ngo 1.22\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.ModulePath).To(Equal("example.com/app"))
					Expect(info.LocalReplaceTargets).To(BeEmpty())
				}),
			),
			Entry(
				"single local replace",
				"module example.com/app\n\nreplace example.com/old => ./local/old\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.ModulePath).To(Equal("example.com/app"))
					Expect(info.LocalReplaceTargets).To(Equal([]string{"example.com/old"}))
					Expect(info.LocalReplacePaths).To(Equal([]string{"./local/old"}))
				}),
			),
			Entry(
				"nested local replace path",
				"module example.com/app\n\nreplace example.com/old => ../vendor/old/subdir\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.LocalReplaceTargets).To(Equal([]string{"example.com/old"}))
					Expect(info.LocalReplacePaths).To(Equal([]string{"../vendor/old/subdir"}))
				}),
			),
			Entry(
				"absolute local replace path",
				"module example.com/app\n\nreplace example.com/old => /tmp/old\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.LocalReplaceTargets).To(Equal([]string{"example.com/old"}))
					Expect(info.LocalReplacePaths).To(Equal([]string{"/tmp/old"}))
				}),
			),
			Entry(
				"module replace is skipped",
				"module example.com/app\n\nreplace example.com/bad => example.com/good v1.2.3\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.LocalReplaceTargets).To(BeEmpty())
					Expect(info.LocalReplacePaths).To(BeEmpty())
				}),
			),
			Entry(
				"mixed local and module replaces",
				"module example.com/app\n\nreplace example.com/old => ./local/old\nreplace example.com/bad => example.com/good v1.2.3\n",
				Succeed(),
				infoAssert(func(info *GoModInfo) {
					Expect(info.LocalReplaceTargets).To(Equal([]string{"example.com/old"}))
					Expect(info.LocalReplacePaths).To(Equal([]string{"./local/old"}))
				}),
			),
		)
	})
})
