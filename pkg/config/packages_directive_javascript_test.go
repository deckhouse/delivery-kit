package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/common-go/pkg/util"
)

var _ = Describe("rawPackagesDirective javascript", func() {
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

		Entry("javascript-npm with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-npm", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptNpm,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "package.json",
						Lock:    "package-lock.json",
					},
				},
			},
		),

		Entry("javascript-npm with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "javascript-npm",
						"workdir": "/app",
						"spec":    "app/package.json",
						"lock":    "app/package-lock.json",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptNpm,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "app/package.json",
						Lock:    "app/package-lock.json",
					},
				},
			},
		),

		Entry("javascript-yarn with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-yarn", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptYarn,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "package.json",
						Lock:    "yarn.lock",
					},
				},
			},
		),

		Entry("javascript-pnpm with only workdir defaults spec and lock",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-pnpm", "workdir": "/app"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "package.json",
						Lock:    "pnpm-lock.yaml",
					},
				},
			},
		),

		Entry("javascript-pnpm with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "javascript-pnpm",
						"workdir": "/app",
						"spec":    "custom/package.json",
						"lock":    "custom/pnpm-lock.yaml",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "custom/package.json",
						Lock:    "custom/pnpm-lock.yaml",
					},
				},
			},
		),

		Entry("javascript-yarn with explicit spec and lock overrides defaults",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{
						"type":    "javascript-yarn",
						"workdir": "/app",
						"spec":    "yarn/package.json",
						"lock":    "yarn/yarn.lock",
					},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptYarn,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "yarn/package.json",
						Lock:    "yarn/yarn.lock",
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

		Entry("javascript-npm without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-npm"},
				},
			},
		),

		Entry("javascript-yarn without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-yarn"},
				},
			},
		),

		Entry("javascript-pnpm without workdir",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-pnpm"},
				},
			},
		),

		Entry("unknown javascript type is rejected (javascript-bower)",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-bower", "workdir": "/app"},
				},
			},
		),
	)
})

var _ = Describe("rawPackagesDirective javascript mixed config", func() {
	var localGitRepo *LocalGitRepoStub
	var giterminismManager *GiterminismManagerStub

	BeforeEach(func() {
		parentStack = util.NewStack()
		localGitRepo = NewLocalGitRepoStub("9d8059842b6fde712c58315ca0ab4713d90761c0")
		giterminismManager = NewGiterminismManagerStub(localGitRepo)
	})

	DescribeTable("mixed config and monorepo scenarios",
		func(ctx SpecContext, yamlMap map[string]interface{}, expected []*PackagesDirective) {
			packages, err := directivesFromYaml(ctx, giterminismManager, yamlMap)
			Expect(err).To(Succeed())

			Expect(packages).To(HaveLen(len(expected)))
			for i, exp := range expected {
				Expect(packages[i].Type).To(Equal(exp.Type))
				Expect(packages[i].FileBased).To(Equal(exp.FileBased))
			}
		},

		Entry("go-mod + javascript-npm + os-pm combined config parses correctly",
			map[string]interface{}{
				"image": "image1",
				"from":  "ubuntu:22.04",
				"packages": []map[string]interface{}{
					{"type": "go-mod", "workdir": "/app"},
					{"type": "javascript-npm", "workdir": "/app/web"},
					{"type": "os-pm"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeGoMod,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "go.mod",
						Lock:    "go.sum",
					},
				},
				{
					Type: PackagesDirectiveTypeJavaScriptNpm,
					FileBased: FileBasedSpec{
						Workdir: "/app/web",
						Spec:    "package.json",
						Lock:    "package-lock.json",
					},
				},
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
				},
			},
		),

		Entry("multiple javascript-* entries with different types and workdirs",
			map[string]interface{}{
				"image": "image1",
				"from":  "node:20-alpine",
				"packages": []map[string]interface{}{
					{"type": "javascript-npm", "workdir": "/app"},
					{"type": "javascript-pnpm", "workdir": "/app/packages/sdk"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeJavaScriptNpm,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "package.json",
						Lock:    "package-lock.json",
					},
				},
				{
					Type: PackagesDirectiveTypeJavaScriptPnpm,
					FileBased: FileBasedSpec{
						Workdir: "/app/packages/sdk",
						Spec:    "package.json",
						Lock:    "pnpm-lock.yaml",
					},
				},
			},
		),

		Entry("go-mod + rust-cargo + javascript-yarn + os-pm combined config",
			map[string]interface{}{
				"image": "image1",
				"from":  "ubuntu:22.04",
				"packages": []map[string]interface{}{
					{"type": "go-mod", "workdir": "/app"},
					{"type": "rust-cargo", "workdir": "/app/native"},
					{"type": "javascript-yarn", "workdir": "/app/web"},
					{"type": "os-pm"},
				},
			},
			[]*PackagesDirective{
				{
					Type: PackagesDirectiveTypeGoMod,
					FileBased: FileBasedSpec{
						Workdir: "/app",
						Spec:    "go.mod",
						Lock:    "go.sum",
					},
				},
				{
					Type: PackagesDirectiveTypeRustCargo,
					FileBased: FileBasedSpec{
						Workdir: "/app/native",
						Spec:    "Cargo.toml",
						Lock:    "Cargo.lock",
					},
				},
				{
					Type: PackagesDirectiveTypeJavaScriptYarn,
					FileBased: FileBasedSpec{
						Workdir: "/app/web",
						Spec:    "package.json",
						Lock:    "yarn.lock",
					},
				},
				{
					Type: PackagesDirectiveTypeOSPM,
					FileBased: FileBasedSpec{
						Spec: "pm.yaml",
						Lock: "pm.lock",
					},
				},
			},
		),
	)
})
