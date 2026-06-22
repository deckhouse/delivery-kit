package config

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	pkgsbom "github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/pkg/sbom/cyclonedxutil/gost"
)

var _ = Describe("buildImageSbom", func() {
	DescribeTable("validate and build image sbom",
		func(meta *Meta, raw *rawSbom, d *doc, errMatcher OmegaMatcher, expectConfigErr bool, validate func(*Sbom)) {
			sbomDirective, err := buildImageSbom(meta, raw, d)
			Expect(err).To(errMatcher)

			if err != nil {
				if expectConfigErr {
					var confErr *configError
					Expect(errors.As(err, &confErr)).To(BeTrue())
				}
				return
			}

			if validate != nil {
				validate(sbomDirective)
			}
		},
		Entry(
			"should fail when build.sbom.enable=false and image sbom is specified",
			&Meta{
				Build: MetaBuild{
					Sbom: &MetaBuildSbom{
						Enable:   false,
						Standard: pkgsbom.StandardTypeCycloneDX16,
					},
				},
			},
			&rawSbom{},
			&doc{RenderFilePath: "werf.yaml", Content: []byte("image: test")},
			HaveOccurred(),
			true,
			nil,
		),
		Entry(
			"GOST logic [1]: should use default 'yes' values when no GOST config is provided",
			&Meta{
				Build: MetaBuild{
					Sbom: &MetaBuildSbom{
						Enable:   true,
						Standard: pkgsbom.StandardTypeCycloneDX16,
						Gost:     gost.DefaultConfig(),
					},
				},
			},
			nil,
			&doc{RenderFilePath: "werf.yaml", Content: []byte("image: test")},
			Succeed(),
			false,
			func(sbomDirective *Sbom) {
				Expect(sbomDirective).ToNot(BeNil())
				Expect(sbomDirective.Gost.AttackSurface).To(Equal(gost.GostValueYes))
				Expect(sbomDirective.Gost.SecurityFunction).To(Equal(gost.GostValueYes))
			},
		),
		Entry(
			"GOST logic [2]: should use values from meta when specified there",
			&Meta{
				Build: MetaBuild{
					Sbom: &MetaBuildSbom{
						Enable:   true,
						Standard: pkgsbom.StandardTypeCycloneDX16,
						Gost: gost.Config{
							AttackSurface:    gost.GostValueNo,
							SecurityFunction: gost.GostValueNo,
						},
					},
				},
			},
			nil,
			&doc{RenderFilePath: "werf.yaml", Content: []byte("image: test")},
			Succeed(),
			false,
			func(sbomDirective *Sbom) {
				Expect(sbomDirective).ToNot(BeNil())
				Expect(sbomDirective.Gost.AttackSurface).To(Equal(gost.GostValueNo))
				Expect(sbomDirective.Gost.SecurityFunction).To(Equal(gost.GostValueNo))
			},
		),
		Entry(
			"GOST logic [3]: should use values from image when specified only there (with defaults fallback)",
			&Meta{
				Build: MetaBuild{
					Sbom: &MetaBuildSbom{
						Enable:   true,
						Standard: pkgsbom.StandardTypeCycloneDX16,
						Gost:     gost.DefaultConfig(),
					},
				},
			},
			&rawSbom{
				Gost: &rawGost{
					AttackSurface: lo.ToPtr("indirect"),
				},
			},
			&doc{RenderFilePath: "werf.yaml", Content: []byte("image: test")},
			Succeed(),
			false,
			func(sbomDirective *Sbom) {
				Expect(sbomDirective).ToNot(BeNil())
				Expect(sbomDirective.Gost.AttackSurface).To(Equal(gost.GostValueIndirect))
				Expect(sbomDirective.Gost.SecurityFunction).To(Equal(gost.GostValueYes))
			},
		),
		Entry(
			"GOST logic [4]: should override meta config with image config",
			&Meta{
				Build: MetaBuild{
					Sbom: &MetaBuildSbom{
						Enable:   true,
						Standard: pkgsbom.StandardTypeCycloneDX16,
						Gost: gost.Config{
							AttackSurface:    gost.GostValueYes,
							SecurityFunction: gost.GostValueNo,
						},
					},
				},
			},
			&rawSbom{
				Gost: &rawGost{
					AttackSurface: lo.ToPtr("no"),
				},
			},
			&doc{RenderFilePath: "werf.yaml", Content: []byte("image: test")},
			Succeed(),
			false,
			func(sbomDirective *Sbom) {
				Expect(sbomDirective).ToNot(BeNil())
				Expect(sbomDirective.Gost.AttackSurface).To(Equal(gost.GostValueNo))
				Expect(sbomDirective.Gost.SecurityFunction).To(Equal(gost.GostValueNo))
			},
		),
	)
})
