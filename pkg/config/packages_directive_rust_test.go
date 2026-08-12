package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective rust-cargo", func() {
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

		Entry("rust-cargo with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "rust:1.78-alpine",
				"packages": []map[string]interface{}{
					{"type": "rust-cargo", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRustCargo,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "Cargo.toml",
						Lock:    "Cargo.lock",
					},
				},
			},
		),

		Entry("rust-cargo with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "rust:1.78-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "rust-cargo",
						"workdir": "/app",
						"spec":    "crate/Cargo.toml",
						"lock":    "crate/Cargo.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeRustCargo,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "crate/Cargo.toml",
						Lock:    "crate/Cargo.lock",
					},
				},
			},
		),
	)

	DescribeTable("convert to directive fails when required fields are missing",
		func(ctx SpecContext, yamlMap map[string]interface{}) {
			_, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(HaveOccurred())
		},

		Entry("rust-cargo without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "rust:1.78-alpine",
				"packages": []map[string]interface{}{
					{"type": "rust-cargo"},
				},
			},
		),

		Entry("cargo alias is rejected (aliases not supported)",
			map[string]interface{}{
				"image": "image1",
				"from":  "rust:1.78-alpine",
				"packages": []map[string]interface{}{
					{"type": "cargo", "workdir": "/app"},
				},
			},
		),
	)
})
