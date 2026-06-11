package stage

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v2/pkg/config"
	"github.com/werf/werf/v2/pkg/container_backend/stage_builder"
	imagePkg "github.com/werf/werf/v2/pkg/image"
)

var _ = Describe("PackagesInstallStage", func() {
	DescribeTable("GeneratePackagesInstallStage", testGeneratePackagesInstallStage,
		Entry("returns nil when Packages is nil",
			&config.StapelImageBase{},
			BeNil(),
		),

		Entry("returns nil when Packages is empty",
			&config.StapelImageBase{
				Packages: []*config.PackagesDirective{},
			},
			BeNil(),
		),

		Entry("returns nil when Packages has empty spec",
			&config.StapelImageBase{
				Packages: []*config.PackagesDirective{
					{
						Type: config.PackagesDirectiveTypeOSPM,
					},
				},
			},
			BeNil(),
		),

		Entry("creates stage with single package",
			&config.StapelImageBase{
				Packages: []*config.PackagesDirective{
					{
						Type: config.PackagesDirectiveTypeOSPM,
						Spec: config.PackagesSpec{Packages: []string{"curl"}},
					},
				},
			},
			ConsistOf("curl"),
		),

		Entry("creates stage with multiple packages",
			&config.StapelImageBase{
				Packages: []*config.PackagesDirective{
					{
						Type: config.PackagesDirectiveTypeOSPM,
						Spec: config.PackagesSpec{Packages: []string{"curl", "jq"}},
					},
				},
			},
			ConsistOf("curl", "jq"),
		),
	)

	Describe("GetDependencies", func() {
		DescribeTable("should return deterministic hash based on resolved packages",
			func(ctx context.Context, packages []string) {
				stage := &PackagesInstallStage{
					resolvedPackages: packages,
					BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{}),
				}
				digest, err := stage.GetDependencies(ctx, nil, nil, nil, nil, nil)
				Expect(err).To(Succeed())

				expected := util.Sha256Hash(packages...)
				Expect(digest).To(Equal(expected))
			},

			Entry("empty list", []string{}),
			Entry("single package", []string{"curl"}),
			Entry("multiple packages", []string{"curl", "jq"}),
		)

		It("should be consistent for same packages", func(ctx context.Context) {
			stage1 := &PackagesInstallStage{
				resolvedPackages: []string{"curl", "jq"},
				BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{}),
			}
			stage2 := &PackagesInstallStage{
				resolvedPackages: []string{"curl", "jq"},
				BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{}),
			}

			digest1, err := stage1.GetDependencies(ctx, nil, nil, nil, nil, nil)
			Expect(err).To(Succeed())

			digest2, err := stage2.GetDependencies(ctx, nil, nil, nil, nil, nil)
			Expect(err).To(Succeed())

			Expect(digest1).To(Equal(digest2))
		})

		It("should produce different hashes for different packages", func(ctx context.Context) {
			stage1 := &PackagesInstallStage{
				resolvedPackages: []string{"curl"},
				BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{}),
			}
			stage2 := &PackagesInstallStage{
				resolvedPackages: []string{"jq"},
				BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{}),
			}

			digest1, err := stage1.GetDependencies(ctx, nil, nil, nil, nil, nil)
			Expect(err).To(Succeed())

			digest2, err := stage2.GetDependencies(ctx, nil, nil, nil, nil, nil)
			Expect(err).To(Succeed())

			Expect(digest1).NotTo(Equal(digest2))
		})
	})

	Describe("PrepareImage", func() {
		const commit = "9d8059842b6fde712c58315ca0ab4713d90761c0"

		It("should prepare image with stapel builder and add commands", func(ctx SpecContext) {
			conveyor := &nonLegacyDependenciesConveyorStub{
				ConveyorStub: NewConveyorStubForDependencies(
					NewGiterminismManagerStub(NewLocalGitRepoStub(commit), NewGiterminismInspectorStub()),
					nil,
				),
			}
			containerBackend := NewContainerBackendStub()

			stage := &PackagesInstallStage{
				resolvedPackages: []string{"curl", "jq"},
				BaseStage:        NewBaseStage(PackagesInstall, &BaseStageOptions{ImageName: "test-image"}),
			}

			_, stageBuilder, stageImage := newStageImage(containerBackend)

			err := stage.PrepareImage(ctx, conveyor, containerBackend, nil, stageImage, nil)
			Expect(err).To(Succeed())

			sb := stageBuilder.GetStapelStageBuilderImplementation()
			Expect(sb).NotTo(BeNil())
			Expect(sb.Commands).To(ContainElement("pm install curl jq"))
			Expect(sb.Labels).To(ContainElement(fmt.Sprintf("%s=%s", imagePkg.WerfProjectRepoCommitLabel, commit)))
		})
	})
})

func testGeneratePackagesInstallStage(ctx context.Context, imageBaseConfig *config.StapelImageBase, packagesMatcher types.GomegaMatcher) {
	options := &BaseStageOptions{ImageName: "test-image", ProjectName: "test-project"}
	stage := GeneratePackagesInstallStage(ctx, imageBaseConfig, options)

	var packages []string
	if stage != nil {
		packages = stage.resolvedPackages
	}
	Expect(packages).To(packagesMatcher)
}

func newStageImage(containerBackend *ContainerBackendStub) (*LegacyImageStub, *stage_builder.StageBuilder, *StageImage) {
	img := NewLegacyImageStub()
	stageBuilder := stage_builder.NewStageBuilder(containerBackend, "", img)

	return img, stageBuilder, &StageImage{
		Image:   img,
		Builder: stageBuilder,
	}
}
