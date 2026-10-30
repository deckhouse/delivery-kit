package build

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/logging"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func debComponent(ref, name, version string) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: name, Version: version,
		PackageURL: "pkg:deb/debian/" + name + "@" + version + "?arch=amd64",
	}
}

func judgement(comp cdx.Component) (string, bool) {
	for _, property := range lo.FromPtr(comp.Properties) {
		if property.Name == shippedscope.PropertyShipped {
			return property.Value, true
		}
	}

	return "", false
}

var _ = Describe("Placing the packages an image inherited", func() {
	// The database of this image records what was installed into it, which is what its
	// base brought and what the build added. It knows nothing of the packages of an
	// image an import copied from, and the paths it holds for a name of its own would
	// be the wrong paths for that other image's package of the same name.
	It("is given the document of the base alone, and leaves the documents of imports untouched", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		base := cyclonedxutil.NewBOM()
		base.Components = &[]cdx.Component{debComponent("base-libfoo", "libfoo", "1.0")}
		imported := cyclonedxutil.NewBOM()
		imported.Components = &[]cdx.Component{
			debComponent("imported-libfoo", "libfoo", "9.9"),
			debComponent("imported-libquux", "libquux", "3.0"),
		}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, base)).To(Succeed())

		Expect(recordedPaths((*base.Components)[0])).To(ConsistOf("/app/lib/libfoo.so"))
		for _, comp := range *imported.Components {
			Expect(comp.Evidence).To(BeNil(), comp.BOMRef)
			_, judged := judgement(comp)
			Expect(judged).To(BeFalse(), comp.BOMRef+" is a package of another image, and this database says nothing of it")
		}
	})

	// An import of the whole of another image carries that image's own package
	// database with it; the one read here is this image's, and the version it records
	// for a name is no verdict on the version another image installed.
	It("leaves a package of another version an import brought in to be scoped as it arrived", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		imported := cyclonedxutil.NewBOM()
		imported.Components = &[]cdx.Component{debComponent("imported-libfoo", "libfoo", "9.9")}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, cyclonedxutil.NewBOM())).To(Succeed())

		scoped, err := scopeImportBOM(ctx, imported,
			[]nativegate.ImportScope{{Backend: nativegate.ImportBackendCopyRecurse, FromPath: "/", ToPath: "/"}})

		Expect(err).NotTo(HaveOccurred())
		Expect(componentNames(scoped)).To(ConsistOf("libfoo"))
		_, judged := judgement((*scoped.Components)[0])
		Expect(judged).To(BeFalse())
	})

	// The verdict is written on the base document before the merge, and the scanned
	// document is marked after it. Between the two sits MarkNotShipped, which clears the
	// verdicts of a donor - and must leave standing the one this image just made about a
	// package of an ecosystem it cannot judge, or the whole pass would write nothing that
	// reaches the published document.
	It("publishes the verdict it made, through the order the convergence runs in", func(specCtx SpecContext) {
		ctx := logging.WithLogger(specCtx)
		base := cyclonedxutil.NewBOM()
		base.Components = &[]cdx.Component{
			debComponent("base-libfoo", "libfoo", "1.0"),
			debComponent("base-gone", "libgone", "4.0"),
		}

		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())
		Expect((&sbomStep{}).placeInheritedPackages(ctx, "app", img, base)).To(Succeed())

		// From here on, the order of ConvergeWithMerge: merge the base into the
		// scanned document, canonicalize, then mark the file evidence of the result.
		scanned := cyclonedxutil.NewBOM()
		published, err := cyclonedxutil.MergeBOMs(ctx, scanned, cyclonedxutil.MergeOpts{BaseBOM: base})
		Expect(err).NotTo(HaveOccurred())
		cyclonedxutil.Canonicalize(ctx, published)
		filesets, err := shippedscope.CollectFilesets(ctx, img)
		Expect(err).NotTo(HaveOccurred())
		recordShippedScope(ctx, published, filesets, &shippedscope.ProducedFiles{}, "app")

		verdicts := map[string]string{}
		paths := map[string][]string{}
		for _, comp := range *published.Components {
			value, judged := judgement(comp)
			if judged {
				verdicts[comp.Name] = value
			}
			paths[comp.Name] = recordedPaths(comp)
		}
		Expect(verdicts).To(HaveKeyWithValue("libgone", shippedscope.PropertyShippedFalse),
			"the package the database never heard of is published as one this image does not ship")
		Expect(paths["libfoo"]).To(ConsistOf("/app/lib/libfoo.so"))
	})

	It("reads no database for an image whose base states nothing", func(specCtx SpecContext) {
		img, err := inheritedPackageImage()
		Expect(err).NotTo(HaveOccurred())

		Expect((&sbomStep{}).placeInheritedPackages(logging.WithLogger(specCtx), "app", img, nil)).To(Succeed())
	})
})

func recordedPaths(comp cdx.Component) []string {
	paths := make([]string, 0)
	for _, occurrence := range lo.FromPtr(lo.FromPtr(comp.Evidence).Occurrences) {
		paths = append(paths, occurrence.Location)
	}

	return paths
}
