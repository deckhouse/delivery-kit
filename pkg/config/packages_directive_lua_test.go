package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective lua-rock", func() {
	var localGitRepo *LocalGitRepoStub
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		localGitRepo = NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
		giterminismManager = NewGiterminismManagerStub(localGitRepo)
	})

	DescribeTable("unmarshal and convert succeed",
		func(ctx SpecContext, yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].FileBased).To(Equal(exp.FileBased))
			}
		},

		Entry("lua-rock with explicit spec keeps empty lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "lua-rock", "workdir": "/app", "spec": "app-0.1-1.rockspec"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeLuaRock,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "app-0.1-1.rockspec",
						Lock:    "",
					},
				},
			},
		),

		Entry("lua-rock with nested spec path",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "lua-rock", "workdir": "/src", "spec": "rockspecs/app-0.1-1.rockspec"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeLuaRock,
					FileBased: FileBasedSpec{
						Workdir: "/src",
						Spec:    "rockspecs/app-0.1-1.rockspec",
						Lock:    "",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("lua-rock without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "lua-rock", "spec": "app-0.1-1.rockspec"},
				},
			},
		),

		Entry("lua-rock without spec (no default rockspec name)",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "lua-rock", "workdir": "/app"},
				},
			},
		),

		Entry("lua-rock with lock is rejected (no lock semantics)",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "lua-rock", "workdir": "/app", "spec": "app-0.1-1.rockspec", "lock": "app.lock"},
				},
			},
		),

		Entry("luarocks alias is rejected (aliases not supported)",
			map[string]interface{}{
				"image": "image1",
				"from":  "nickblah/lua:5.4",
				"packages": []map[string]interface{}{
					{"type": "luarocks", "workdir": "/app", "spec": "app-0.1-1.rockspec"},
				},
			},
		),
	)
})
