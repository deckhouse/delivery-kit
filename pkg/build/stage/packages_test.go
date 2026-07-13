package stage

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/config"
)

var _ = Describe("PackagesStage", func() {
	Describe("GeneratePackagesStage", func() {
		DescribeTable("returns nil when no packages commands",
			func(ctx context.Context, imageBaseConfig *config.StapelImageBase) {
				stage := GeneratePackagesStage(ctx, imageBaseConfig, testGitPatchOpts(), testBaseOpts())
				Expect(stage).To(BeNil())
			},

			Entry("nil shell", &config.StapelImageBase{}),
			Entry("shell without packages", &config.StapelImageBase{Shell: &config.Shell{Install: []string{"echo hi"}}}),
			Entry("shell with empty packages", &config.StapelImageBase{Shell: &config.Shell{Packages: []string{}}}),
		)

		It("returns stage when packages commands present", func(ctx context.Context) {
			stage := generateTestPackagesStage(ctx, "cd \"/app\" && go mod download")
			Expect(stage).NotTo(BeNil())
		})
	})

	DescribeTable("NeedsNetwork",
		func(ctx context.Context, stageName StageName, needsNetwork, expected bool) {
			s := NewBaseStage(stageName, &BaseStageOptions{NeedsNetwork: needsNetwork})
			Expect(s.NeedsNetwork()).To(Equal(expected))
		},

		Entry("packages stage created with NeedsNetwork=true", Packages, true, true),
		Entry("install stage has NeedsNetwork=false", Install, false, false),
		Entry("setup stage has NeedsNetwork=false", Setup, false, false),
		Entry("beforeInstall has NeedsNetwork=false", BeforeInstall, false, false),
	)

	It("Name returns packages", func(ctx context.Context) {
		stage := generateTestPackagesStage(ctx, "cd \"/app\" && go mod download")
		Expect(stage.Name()).To(Equal(Packages))
	})

	Describe("GetDependencies", func() {
		DescribeTable("hash behavior",
			func(ctx context.Context, commands1, commands2 []string, shouldEqual bool) {
				s1 := generateTestPackagesStageMulti(ctx, commands1)
				s2 := generateTestPackagesStageMulti(ctx, commands2)
				conveyor := testConveyor()

				d1, err := s1.GetDependencies(ctx, conveyor, nil, nil, nil, nil)
				Expect(err).NotTo(HaveOccurred())

				d2, err := s2.GetDependencies(ctx, conveyor, nil, nil, nil, nil)
				Expect(err).NotTo(HaveOccurred())

				if shouldEqual {
					Expect(d1).To(Equal(d2))
				} else {
					Expect(d1).NotTo(Equal(d2))
				}
			},

			Entry("same commands produce same hash",
				[]string{"cd \"/app\" && go mod download"},
				[]string{"cd \"/app\" && go mod download"},
				true),
			Entry("different commands produce different hash",
				[]string{"cd \"/app\" && go mod download"},
				[]string{"cd \"/lib\" && go mod download"},
				false),
			Entry("different number of commands produce different hash",
				[]string{"cd \"/app\" && go mod download"},
				[]string{"cd \"/app\" && go mod download", "cd \"/lib\" && go mod download"},
				false),
		)

		It("returns non-empty hash", func(ctx context.Context) {
			s := generateTestPackagesStage(ctx, "cd \"/app\" && go mod download")
			digest, err := s.GetDependencies(ctx, testConveyor(), nil, nil, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(digest).NotTo(BeEmpty())
		})
	})

	Describe("coexistence with other stages", func() {
		It("does not affect install stage creation", func(ctx context.Context) {
			imageBaseConfig := &config.StapelImageBase{
				Shell: &config.Shell{
					Packages: []string{"cd \"/app\" && go mod download"},
					Install:  []string{"go build ./..."},
				},
			}

			packagesStage := GeneratePackagesStage(ctx, imageBaseConfig, testGitPatchOpts(), testBaseOpts())
			installStage := GenerateInstallStage(ctx, imageBaseConfig, testGitPatchOpts(), testBaseOpts())

			Expect(packagesStage).NotTo(BeNil())
			Expect(installStage).NotTo(BeNil())
			Expect(packagesStage.Name()).NotTo(Equal(installStage.Name()))
		})
	})
})

var _ = Describe("NetworkOverride enforcement", func() {
	DescribeTable("BaseStage network resolution",
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

		Entry("override=none takes priority over host", "host", "none", "none"),
		Entry("override=none with empty network", "", "none", "none"),
		Entry("empty override uses image network", "host", "", "host"),
		Entry("both empty stays empty", "", "", ""),
	)
})

var _ = Describe("Network enforcement logic", func() {
	DescribeTable("stageHasNetworkAccess",
		func(stageName StageName, needsNetwork, expected bool) {
			s := NewBaseStage(stageName, &BaseStageOptions{NeedsNetwork: needsNetwork})
			Expect(testStageHasNetworkAccess(s)).To(Equal(expected))
		},

		Entry("From without flag — no network", From, false, false),
		Entry("GitArchive without flag — no network", GitArchive, false, false),
		Entry("GitCache without flag — no network", GitCache, false, false),
		Entry("GitLatestPatch without flag — no network", GitLatestPatch, false, false),
		Entry("Install without flag — no network", Install, false, false),
		Entry("Setup without flag — no network", Setup, false, false),
		Entry("BeforeInstall without flag — no network", BeforeInstall, false, false),
		Entry("BeforeSetup without flag — no network", BeforeSetup, false, false),
		Entry("Packages with NeedsNetwork=true — has network", Packages, true, true),
		Entry("arbitrary stage with flag — has network", StageName("custom"), true, true),
		Entry("arbitrary stage without flag — no network", StageName("custom"), false, false),
	)
})

var _ = Describe("GeneratePackagesCommands", func() {
	DescribeTable("command generation",
		func(packages []*config.PackagesDirective, expected []string) {
			Expect(config.GeneratePackagesCommands(packages)).To(Equal(expected))
		},

		Entry("go-mod /app", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/app"}},
		}, []string{"cd \"/app\" && go mod download"}),

		Entry("go-mod /src/backend", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/src/backend"}},
		}, []string{"cd \"/src/backend\" && go mod download"}),

		Entry("multiple go-mod entries", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/app"}},
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/lib"}},
		}, []string{"cd \"/app\" && go mod download", "cd \"/lib\" && go mod download"}),

		Entry("root workdir", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/"}},
		}, []string{"cd \"/\" && go mod download"}),

		Entry("unsupported type", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveType("unknown")},
		}, ([]string)(nil)),

		Entry("nil packages", []*config.PackagesDirective(nil), ([]string)(nil)),

		Entry("os-pm single package", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeOSPM, Spec: config.PackagesSpec{Packages: []string{"curl"}}},
		}, []string{config.ContainerFactoryVersionSnapshotCmd(), "pm install curl"}),

		Entry("os-pm multiple packages", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeOSPM, Spec: config.PackagesSpec{Packages: []string{"curl", "wget", "jq"}}},
		}, []string{config.ContainerFactoryVersionSnapshotCmd(), "pm install curl", "pm install wget", "pm install jq"}),

		Entry("mixed types: os-pm and go-mod skip unknown type", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeOSPM, Spec: config.PackagesSpec{Packages: []string{"curl"}}},
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/app"}},
			{Type: config.PackagesDirectiveType("cargo")},
		}, []string{config.ContainerFactoryVersionSnapshotCmd(), "pm install curl", "cd \"/app\" && go mod download"}),

		Entry("python-pip /app requirements.txt", []*config.PackagesDirective{
			{
				Type:      config.PackagesDirectiveTypePythonPip,
				FileBased: config.FileBasedSpec{Workdir: "/app", Spec: "requirements.txt"},
			},
		}, []string{"cd \"/app\" && pip install --no-cache-dir -r \"requirements.txt\""}),

		Entry("python-poetry /svc", []*config.PackagesDirective{
			{
				Type:      config.PackagesDirectiveTypePythonPoetry,
				FileBased: config.FileBasedSpec{Workdir: "/svc"},
			},
		}, []string{"cd \"/svc\" && poetry sync --no-root"}),

		Entry("python-uv /api", []*config.PackagesDirective{
			{
				Type:      config.PackagesDirectiveTypePythonUV,
				FileBased: config.FileBasedSpec{Workdir: "/api"},
			},
		}, []string{"cd \"/api\" && uv sync --frozen"}),

		Entry("mixed: go-mod + python-uv + os-pm all produce commands", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/app"}},
			{
				Type:      config.PackagesDirectiveTypePythonUV,
				FileBased: config.FileBasedSpec{Workdir: "/lib"},
			},
			{Type: config.PackagesDirectiveTypeOSPM, Spec: config.PackagesSpec{Packages: []string{"curl"}}},
		}, []string{"cd \"/app\" && go mod download", "cd \"/lib\" && uv sync --frozen", config.ContainerFactoryVersionSnapshotCmd(), "pm install curl"}),

		Entry("rust-cargo /app produces cargo fetch", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/app"}},
		}, []string{"cd \"/app\" && cargo fetch"}),

		Entry("rust-cargo /src/service produces cargo fetch", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/src/service"}},
		}, []string{"cd \"/src/service\" && cargo fetch"}),

		Entry("rust-cargo workdir with spaces is quoted", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/my app/crate"}},
		}, []string{"cd \"/my app/crate\" && cargo fetch"}),

		Entry("multiple rust-cargo entries", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/app"}},
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/lib"}},
		}, []string{"cd \"/app\" && cargo fetch", "cd \"/lib\" && cargo fetch"}),

		Entry("mixed: rust-cargo + go-mod + os-pm all produce commands", []*config.PackagesDirective{
			{Type: config.PackagesDirectiveTypeRustCargo, FileBased: config.FileBasedSpec{Workdir: "/app"}},
			{Type: config.PackagesDirectiveTypeGoMod, FileBased: config.FileBasedSpec{Workdir: "/tools"}},
			{Type: config.PackagesDirectiveTypeOSPM, Spec: config.PackagesSpec{Packages: []string{"libssl-dev"}}},
		}, []string{"cd \"/app\" && cargo fetch", "cd \"/tools\" && go mod download", config.ContainerFactoryVersionSnapshotCmd(), "pm install libssl-dev"}),
	)
})

var _ = Describe("stageDependencies.packages", func() {
	DescribeTable("config field",
		func(packages, expected []string) {
			sd := &config.StageDependencies{Packages: packages}
			Expect(sd.Packages).To(Equal(expected))
		},

		Entry("single path", []string{"go.sum"}, []string{"go.sum"}),
		Entry("multiple paths", []string{"go.sum", "go.mod"}, []string{"go.sum", "go.mod"}),
		Entry("empty", []string{}, []string{}),
	)

	It("maps to Packages StageName", func() {
		sd := &config.StageDependencies{Packages: []string{"go.sum"}}
		m := map[StageName][]string{
			Install:     sd.Install,
			BeforeSetup: sd.BeforeSetup,
			Setup:       sd.Setup,
			Packages:    sd.Packages,
		}
		Expect(m[Packages]).To(Equal([]string{"go.sum"}))
	})
})

var _ = Describe("Shell.Packages config field", func() {
	DescribeTable("field access",
		func(shell *config.Shell, expectedLen int, expectedFirst string) {
			Expect(shell.Packages).To(HaveLen(expectedLen))
			if expectedLen > 0 {
				Expect(shell.Packages[0]).To(Equal(expectedFirst))
			}
		},

		Entry("populated", &config.Shell{Packages: []string{"cd \"/app\" && go mod download"}}, 1, "cd \"/app\" && go mod download"),
		Entry("empty", &config.Shell{}, 0, ""),
	)

	It("PackagesCacheVersion field", func() {
		Expect((&config.Shell{PackagesCacheVersion: "v2"}).PackagesCacheVersion).To(Equal("v2"))
	})
})

var _ = Describe("Builder interface Packages methods", func() {
	DescribeTable("IsPackagesEmpty",
		func(_ context.Context, shell *config.Shell, expected bool) {
			Expect(testBuilderIsPackagesEmpty(shell)).To(Equal(expected))
		},

		Entry("true when no packages", &config.Shell{Install: []string{"echo"}}, true),
		Entry("false when packages present", &config.Shell{Packages: []string{"cmd"}}, false),
		Entry("true for nil shell", &config.Shell{}, true),
	)

	DescribeTable("PackagesChecksum",
		func(_ context.Context, commands1, commands2 []string, shouldEqual bool) {
			c1 := testBuilderPackagesChecksum(commands1)
			c2 := testBuilderPackagesChecksum(commands2)
			if shouldEqual {
				Expect(c1).To(Equal(c2))
			} else {
				Expect(c1).NotTo(Equal(c2))
			}
		},

		Entry("same commands — same checksum",
			[]string{"cd \"/app\" && go mod download"},
			[]string{"cd \"/app\" && go mod download"},
			true),
		Entry("different commands — different checksum",
			[]string{"cd \"/app\" && go mod download"},
			[]string{"cd \"/lib\" && go mod download"},
			false),
	)

	It("empty packages returns empty checksum", func() {
		Expect(testBuilderPackagesChecksum(nil)).To(BeEmpty())
	})
})

func testBaseOpts() *BaseStageOptions {
	return &BaseStageOptions{ImageName: "test", ContainerWerfDir: "/.werf", ImageTmpDir: "/tmp/test"}
}

func testGitPatchOpts() *NewGitPatchStageOptions {
	return &NewGitPatchStageOptions{}
}

func testConveyor() Conveyor {
	return NewConveyorStubForDependencies(
		NewGiterminismManagerStub(NewLocalGitRepoStub("abc123"), NewGiterminismInspectorStub()),
		nil,
	)
}

func generateTestPackagesStage(ctx context.Context, command string) *PackagesStage {
	return generateTestPackagesStageMulti(ctx, []string{command})
}

func generateTestPackagesStageMulti(ctx context.Context, commands []string) *PackagesStage {
	imageBaseConfig := &config.StapelImageBase{
		Shell: &config.Shell{Packages: commands},
	}
	return GeneratePackagesStage(ctx, imageBaseConfig, testGitPatchOpts(), testBaseOpts())
}

func testStageHasNetworkAccess(s Interface) bool {
	if nn, ok := s.(interface{ NeedsNetwork() bool }); ok {
		return nn.NeedsNetwork()
	}
	return false
}

func testBuilderIsPackagesEmpty(shell *config.Shell) bool {
	return len(shell.Packages) == 0
}

func testBuilderPackagesChecksum(commands []string) string {
	if len(commands) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", commands)
}
