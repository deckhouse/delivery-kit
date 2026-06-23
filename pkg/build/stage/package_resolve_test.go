package stage

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
)

var _ = Describe("NetworkOverride", func() {
	DescribeTable("BaseStage.PrepareImage network resolution",
		func(imageNetwork, override, expectedEffective string) {
			s := NewBaseStage("test", &BaseStageOptions{Network: imageNetwork})
			if override != "" {
				s.SetNetworkOverride(override)
			}

			effective := s.network
			if s.networkOverride != "" {
				effective = s.networkOverride
			}

			Expect(effective).To(Equal(expectedEffective))
		},

		Entry("override=none takes priority over image network=host",
			"host", "none", "none"),
		Entry("override=none takes priority over image network=default",
			"default", "none", "none"),
		Entry("empty override uses image network",
			"host", "", "host"),
		Entry("empty override with empty image network stays empty",
			"", "", ""),
		Entry("override=none with empty image network uses override",
			"", "none", "none"),
	)

	Describe("SetNetworkOverride", func() {
		It("sets the networkOverride field without affecting network", func() {
			s := NewBaseStage("test", &BaseStageOptions{Network: "host"})
			s.SetNetworkOverride("none")

			Expect(s.networkOverride).To(Equal("none"))
			Expect(s.network).To(Equal("host"))
		})
	})
})

var _ = Describe("PackageResolveStage", func() {
	DescribeTable("resolveCommands",
		func(directive *config.PackagesDirective, expectedCommands []string) {
			s := newPackageResolveStage(directive, 0, &BaseStageOptions{})
			Expect(s.resolveCommands()).To(Equal(expectedCommands))
		},

		Entry("go-mod with workdir /app",
			&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			},
			[]string{"cd /app && go mod download"},
		),
		Entry("go-mod with workdir /src/backend",
			&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/src/backend", Spec: "go.mod", Lock: "go.sum"},
			},
			[]string{"cd /src/backend && go mod download"},
		),
		Entry("unsupported type returns nil",
			&config.PackagesDirective{
				Type: config.PackagesDirectiveType("unknown"),
			},
			([]string)(nil),
		),
	)

	DescribeTable("Name includes index for uniqueness",
		func(index int, expectedName StageName) {
			s := newPackageResolveStage(&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}, index, &BaseStageOptions{})
			Expect(s.Name()).To(Equal(expectedName))
		},

		Entry("index 0", 0, StageName("packageResolve0")),
		Entry("index 1", 1, StageName("packageResolve1")),
		Entry("index 5", 5, StageName("packageResolve5")),
	)

	Describe("IsEmpty", func() {
		It("always returns false for a configured directive", func() {
			s := newPackageResolveStage(&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}, 0, &BaseStageOptions{})

			empty, err := s.IsEmpty(nil, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(empty).To(BeFalse())
		})
	})

	Describe("GeneratePackageResolveStage", func() {
		It("returns nil when directive is nil", func() {
			Expect(GeneratePackageResolveStage(nil, 0, &BaseStageOptions{})).To(BeNil())
		})

		It("returns a valid stage when directive is provided", func() {
			d := &config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}
			s := GeneratePackageResolveStage(d, 0, &BaseStageOptions{})
			Expect(s).NotTo(BeNil())
			Expect(s.directive).To(Equal(d))
		})

		DescribeTable("multiple entries produce independent stages",
			func(directives []*config.PackagesDirective, expectedCount int) {
				var stages []*PackageResolveStage
				for i, d := range directives {
					s := GeneratePackageResolveStage(d, i, &BaseStageOptions{})
					if s != nil {
						stages = append(stages, s)
					}
				}
				Expect(stages).To(HaveLen(expectedCount))

				for i, s := range stages {
					Expect(s.Name()).To(Equal(StageName(fmt.Sprintf("packageResolve%d", i))))
				}
			},

			Entry("two go-mod entries", []*config.PackagesDirective{
				{Type: config.PackagesDirectiveTypeGoMod, GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
				{Type: config.PackagesDirectiveTypeGoMod, GoMod: config.GoModSpec{Workdir: "/lib", Spec: "go.mod", Lock: "go.sum"}},
			}, 2),
			Entry("single entry", []*config.PackagesDirective{
				{Type: config.PackagesDirectiveTypeGoMod, GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"}},
			}, 1),
			Entry("nil filtered out", []*config.PackagesDirective{nil}, 0),
		)
	})

	Describe("SetGitMappings", func() {
		It("injects lockfile path into StagesDependencies for go-mod", func() {
			d := &config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}
			s := newPackageResolveStage(d, 0, &BaseStageOptions{})

			gm := NewGitMapping()
			gm.StagesDependencies = make(map[StageName][]string)

			s.SetGitMappings([]*GitMapping{gm})

			Expect(gm.StagesDependencies[s.Name()]).To(Equal([]string{"/app/go.sum"}))
		})

		It("injects lockfile path for multiple git mappings", func() {
			d := &config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/src", Spec: "go.mod", Lock: "go.sum"},
			}
			s := newPackageResolveStage(d, 1, &BaseStageOptions{})

			gm1 := NewGitMapping()
			gm1.StagesDependencies = make(map[StageName][]string)
			gm2 := NewGitMapping()
			gm2.StagesDependencies = make(map[StageName][]string)

			s.SetGitMappings([]*GitMapping{gm1, gm2})

			Expect(gm1.StagesDependencies[StageName("packageResolve1")]).To(Equal([]string{"/src/go.sum"}))
			Expect(gm2.StagesDependencies[StageName("packageResolve1")]).To(Equal([]string{"/src/go.sum"}))
		})

		It("does not inject when lockfilePath is empty (unknown type)", func() {
			d := &config.PackagesDirective{
				Type: config.PackagesDirectiveType("unknown"),
			}
			s := newPackageResolveStage(d, 0, &BaseStageOptions{})

			gm := NewGitMapping()
			gm.StagesDependencies = make(map[StageName][]string)

			s.SetGitMappings([]*GitMapping{gm})

			Expect(gm.StagesDependencies[s.Name()]).To(BeEmpty())
		})

		It("initializes StagesDependencies map if nil", func() {
			d := &config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}
			s := newPackageResolveStage(d, 0, &BaseStageOptions{})

			gm := NewGitMapping()

			s.SetGitMappings([]*GitMapping{gm})

			Expect(gm.StagesDependencies).NotTo(BeNil())
			Expect(gm.StagesDependencies[s.Name()]).To(Equal([]string{"/app/go.sum"}))
		})
	})

	DescribeTable("lockfilePath",
		func(directive *config.PackagesDirective, expectedPath string) {
			s := newPackageResolveStage(directive, 0, &BaseStageOptions{})
			Expect(s.lockfilePath()).To(Equal(expectedPath))
		},

		Entry("go-mod with workdir /app",
			&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			},
			"/app/go.sum",
		),
		Entry("go-mod with custom lock filename",
			&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/src", Spec: "go.mod", Lock: "go.sum.custom"},
			},
			"/src/go.sum.custom",
		),
		Entry("unknown type returns empty",
			&config.PackagesDirective{
				Type: config.PackagesDirectiveType("pip"),
			},
			"",
		),
	)

	Describe("NetworkOverrideValue getter", func() {
		It("returns empty by default", func() {
			s := newPackageResolveStage(&config.PackagesDirective{
				Type:  config.PackagesDirectiveTypeGoMod,
				GoMod: config.GoModSpec{Workdir: "/app", Spec: "go.mod", Lock: "go.sum"},
			}, 0, &BaseStageOptions{})
			Expect(s.NetworkOverrideValue()).To(Equal(""))
		})

		It("returns value after SetNetworkOverride", func() {
			s := NewBaseStage("test", &BaseStageOptions{})
			s.SetNetworkOverride("none")
			Expect(s.NetworkOverrideValue()).To(Equal("none"))
		})
	})
})
