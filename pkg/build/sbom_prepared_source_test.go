package build

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

var _ = Describe("An image declared a prepared source", func() {
	declaring := func(label string) *buildImage.Image {
		img := &buildImage.Image{}
		img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			Name:      "go-source",
			ImageSpec: &config.ImageSpec{Labels: map[string]string{sbomBuildContextLabel: label}},
		}}

		return img
	}

	It("is read off the recipe, and only off the private declaration", func() {
		phase := &BuildPhase{}

		Expect(phase.preparedSourceImage(declaring(`{"version":1,"preparedSource":true}`))).To(BeTrue())
		Expect(phase.preparedSourceImage(declaring(`{"version":1,"bootstrap":true}`))).To(BeFalse())
		Expect(phase.preparedSourceImage(&buildImage.Image{})).To(BeFalse())
	})

	// Declaring a package is what every prepared source image does on its way to being
	// consumed as one; it is not what says this image may collect files without
	// answering for them.
	It("is not read off the package labels of an image", func() {
		img := &buildImage.Image{}
		img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			Name: "go-source",
			ImageSpec: &config.ImageSpec{Labels: map[string]string{
				"pkg.name": "go-source", "pkg.version": "1.27.3", "pkg.type": "source", "pkg.arch": "linux/amd64",
			}},
		}}
		phase := &BuildPhase{}

		Expect(phase.preparedSourceImage(img)).To(BeFalse())
	})

	// The document of a prepared source states where in it each file of its package
	// stands, which is what keeps that package when another image imports a part of it:
	// a component stating no whereabouts at all would be read as a statement about the
	// donor and dropped.
	It("contributes its package to an image importing a part of it", func(specCtx SpecContext) {
		component := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "urn:dk:prepared-source:abc", Name: "go-source", Version: "1.0",
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/src/runtime/defs.h", AdditionalContext: "sha256:" + strings.Repeat("a", 64)},
				{Location: "/src/cmd/main.go", AdditionalContext: "sha256:" + strings.Repeat("b", 64)},
			}},
		}
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{component}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom,
			[]nativegate.ImportScope{{FromPath: "/src/runtime", ToPath: "/opt/runtime"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(*scoped.Components).To(HaveLen(1))
		Expect((*scoped.Components)[0].BOMRef).To(Equal("urn:dk:prepared-source:abc"))
	})

	It("contributes nothing of its package to an image importing a part it does not cover", func(specCtx SpecContext) {
		component := cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: "urn:dk:prepared-source:abc", Name: "go-source", Version: "1.0",
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: "/src/runtime/defs.h", AdditionalContext: "sha256:" + strings.Repeat("a", 64)},
			}},
		}
		bom := cyclonedxutil.NewBOM()
		bom.Components = &[]cdx.Component{component}

		scoped, err := scopeImportBOM(logging.WithLogger(specCtx), bom,
			[]nativegate.ImportScope{{FromPath: "/doc", ToPath: "/opt/doc"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(scoped.Components).To(BeNil())
	})

	It("refuses a declaration it cannot read", func() {
		phase := &BuildPhase{}

		_, err := phase.preparedSourceImage(declaring(`{"version":1,"preparedSource":true,"bootstrap":true}`))
		Expect(err).To(MatchError(ContainSubstring("an image is either a bootstrap image or a prepared source, not both")))
	})

})
