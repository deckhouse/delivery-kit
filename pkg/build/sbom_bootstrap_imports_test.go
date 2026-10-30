package build

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	buildImage "github.com/werf/werf/v3/pkg/build/image"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
)

var _ = Describe("Declared originals of a bootstrap import", func() {
	declaration := func(body string) *buildImage.Image {
		img := &buildImage.Image{}
		img.StapelImageConfig = &config.StapelImage{StapelImageBase: &config.StapelImageBase{
			Name:      "app",
			ImageSpec: &config.ImageSpec{Labels: map[string]string{sbomBuildContextLabel: body}},
		}}

		return img
	}

	const mapped = `{"version":1,"bootstrapOriginals":[
		{"sourceImage":"go-bootstrap","packageName":"go","packageVersion":"1.27.3","root":"/usr/local/go/src","originalPath":"src"},
		{"sourceImage":"go-bootstrap","packageName":"go","packageVersion":"1.27.3","root":"/usr/local/go/pkg/include","originalPath":"src/runtime"}]}`

	bootstrapImport := func(name string) scopedImportImage {
		return scopedImportImage{resolvedImportImage: resolvedImportImage{imageName: name, bootstrap: true}}
	}

	It("hands the verification the mappings the recipe declares for that source", func() {
		phase := &BuildPhase{}

		originals, err := phase.bootstrapImportOriginals(declaration(mapped), []scopedImportImage{bootstrapImport("go-bootstrap")})

		Expect(err).NotTo(HaveOccurred())
		Expect(originals).To(Equal(map[string][]nativegate.ImportOriginal{"go-bootstrap": {
			{Root: "/usr/local/go/src", OriginalPath: "src", PackageName: "go", PackageVersion: "1.27.3"},
			{Root: "/usr/local/go/pkg/include", OriginalPath: "src/runtime", PackageName: "go", PackageVersion: "1.27.3"},
		}}))
	})

	// A mapping is a statement about an import this image performs; for anything else
	// it would describe a copy that never happens.
	It("refuses mappings for a source the image does not import as a bootstrap one", func() {
		phase := &BuildPhase{}

		_, err := phase.bootstrapImportOriginals(declaration(mapped), []scopedImportImage{
			{resolvedImportImage: resolvedImportImage{imageName: "go-bootstrap"}},
		})

		Expect(err).To(MatchError(ContainSubstring(`declares the originals of "go-bootstrap", which it does not import from as a bootstrap image`)))
	})

	It("states nothing for an image whose recipe declares nothing", func() {
		phase := &BuildPhase{}

		originals, err := phase.bootstrapImportOriginals(&buildImage.Image{}, nil)

		Expect(err).NotTo(HaveOccurred())
		Expect(originals).To(BeEmpty())
	})

	DescribeTable("refuses a mapping that states nothing usable",
		func(body, expected string) {
			_, err := parseSBOMBuildContextDeclaration([]byte(body))
			Expect(err).To(MatchError(ContainSubstring(expected)))
		},
		Entry("a root that is not an absolute path",
			`{"version":1,"bootstrapOriginals":[{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"usr/local/go","originalPath":"src"}]}`,
			"root must be a clean absolute path"),
		Entry("a root spelled with a traversal",
			`{"version":1,"bootstrapOriginals":[{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"/usr/local/../local/go","originalPath":"src"}]}`,
			"root must be a clean absolute path"),
		Entry("a path reaching outside the prepared source",
			`{"version":1,"bootstrapOriginals":[{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"/usr/local/go","originalPath":"../src"}]}`,
			"is not a path inside the prepared source"),
		Entry("an absolute path inside the prepared source",
			`{"version":1,"bootstrapOriginals":[{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"/usr/local/go","originalPath":"/src"}]}`,
			"is not a path inside the prepared source"),
		Entry("no prepared source at all",
			`{"version":1,"bootstrapOriginals":[{"sourceImage":"b","packageName":"","packageVersion":"1","root":"/usr/local/go","originalPath":"src"}]}`,
			"packageName is required"),
		Entry("one root mapped twice",
			`{"version":1,"bootstrapOriginals":[
				{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"/usr/local/go","originalPath":"src"},
				{"sourceImage":"b","packageName":"go","packageVersion":"2","root":"/usr/local/go","originalPath":"other"}]}`,
			"is declared more than once"),
		Entry("the originals of a bootstrap image itself",
			`{"version":1,"bootstrap":true,"bootstrapOriginals":[{"sourceImage":"b","packageName":"go","packageVersion":"1","root":"/usr/local/go","originalPath":"src"}]}`,
			"a bootstrap image states the originals of nothing"),
	)

	It("needs no producer stage to state where imported files come from", func() {
		parsed, err := parseSBOMBuildContextDeclaration([]byte(mapped))

		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Stages).To(BeEmpty())
		Expect(parsed.BootstrapOriginals).To(HaveLen(2))
	})

	It("still needs a stage or a mapping to state anything at all", func() {
		_, err := parseSBOMBuildContextDeclaration([]byte(`{"version":1}`))

		Expect(err).To(MatchError(ContainSubstring("at least one stage is required")))
	})
})
