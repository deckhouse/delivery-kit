package nativegate

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

type goModulesFixture struct {
	body     []byte
	expected []byte
	record   shared.BuildRecord
}

func goModulesProducerFixture(name, bodySHA256, expectedSHA256 string) goModulesFixture {
	ginkgo.GinkgoHelper()
	root := os.Getenv("DK_GO_MODULES_FIXTURE")
	if root == "" {
		ginkgo.Skip("requires pinned DK_GO_MODULES_FIXTURE (mandatory in task test:native-poc)")
	}
	body, err := os.ReadFile(filepath.Join(root, name))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(body)).To(gomega.Equal(bodySHA256))
	expected, err := os.ReadFile(filepath.Join(root, name+".sbom.json"))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(expected)).To(gomega.Equal(expectedSHA256))
	var record shared.BuildRecord
	gomega.Expect(json.Unmarshal(expected, &record)).To(gomega.Succeed())
	return goModulesFixture{body: body, expected: expected, record: record}
}

// goModulesCatalog runs the consumer gate with the shipped default policy and
// returns the inventoried libraries together with the single build record.
func goModulesCatalog(ctx ginkgo.SpecContext, f goModulesFixture) (map[string]string, Record) {
	ginkgo.GinkgoHelper()
	bom := cdx.NewBOM()
	gomega.Expect(Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", fixtureImage(map[string]string{"/app": string(f.body)}), nil, bom)).To(gomega.Succeed())
	libraries := map[string]string{}
	for _, component := range *bom.Components {
		if component.Type == cdx.ComponentTypeLibrary {
			libraries[component.Name] = component.Version
		}
	}
	catalog, err := inherited([]*cdx.BOM{bom})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(catalog.Records).To(gomega.HaveLen(1))
	gomega.Expect(catalog.Records[0].Profile).To(gomega.Equal("go"))
	gomega.Expect(catalog.Records[0].Composition).To(gomega.MatchJSON(f.expected))
	return libraries, catalog.Records[0]
}

func goModulesBindings(record Record) []shared.GoModuleBinding {
	ginkgo.GinkgoHelper()
	var composition shared.BuildRecord
	gomega.Expect(json.Unmarshal(record.Composition, &composition)).To(gomega.Succeed())
	gomega.Expect(composition.GoModules).NotTo(gomega.BeNil())
	gomega.Expect(*composition.GoModules).NotTo(gomega.BeEmpty())
	return *composition.GoModules
}

func goModulesComponent(f goModulesFixture, id string) shared.BuildComponent {
	ginkgo.GinkgoHelper()
	for _, component := range f.record.Components {
		if component.ID == id {
			return component
		}
	}
	ginkgo.Fail("unknown component " + id)
	return shared.BuildComponent{}
}

var _ = ginkgo.Describe("Real Go module producer fixtures", func() {
	ginkgo.It("maps a versioned dependency onto its own component", func(ctx ginkgo.SpecContext) {
		fixture := goModulesProducerFixture("go-module-versioned-elf",
			"sha256:309bc007183399cca557943000b2e1e5f1a66557c829485235ea7dc4a166faa7",
			"sha256:eec2cd68a8fb4e8225d38d8a61f59bb8525183037adebec07489290615bed488")
		libraries, record := goModulesCatalog(ctx, fixture)
		gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "example.com/dep": "v1.2.3", "golang": "1.27.3"}))
		bindings := goModulesBindings(record)
		gomega.Expect(bindings).To(gomega.HaveLen(1))
		gomega.Expect(bindings[0]).To(gomega.Equal(shared.GoModuleBinding{Component: "c1", Module: debug.Module{
			Path: "example.com/dep", Version: "v1.2.3", Sum: "h1:CyIUe0f/UcZ7jf72/UrGmCy7XfHiWx+Z3Vgu8q86Jcc=",
		}}))
		dependency := goModulesComponent(fixture, bindings[0].Component)
		gomega.Expect(dependency.Name).To(gomega.Equal(bindings[0].Module.Path))
		gomega.Expect(dependency.Version).To(gomega.Equal(bindings[0].Module.Version))
		gomega.Expect(dependency.Source.Kind).To(gomega.Equal("go"))
		gomega.Expect(dependency.Source.Locator).To(gomega.Equal("example.com/dep@v1.2.3"))
	})

	ginkgo.It("binds a replaced dependency to the replacement component only", func(ctx ginkgo.SpecContext) {
		fixture := goModulesProducerFixture("go-module-replaced-elf",
			"sha256:fae4938464f5548ba6c58fff335390db4ff3317e65b4c01dfd2df9c3e9dbcfcc",
			"sha256:0711ad1f7a63f21449c657444d046708a857c0cee6c2f82994166cdb1550441b")
		libraries, record := goModulesCatalog(ctx, fixture)
		gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "example.com/replacement": "v1.4.0", "golang": "1.27.3"}))
		bindings := goModulesBindings(record)
		gomega.Expect(bindings).To(gomega.HaveLen(1))
		gomega.Expect(bindings[0]).To(gomega.Equal(shared.GoModuleBinding{Component: "c1", Module: debug.Module{
			Path: "example.com/dep", Version: "v1.2.3", Replace: &debug.Module{
				Path: "example.com/replacement", Version: "v1.4.0", Sum: "h1:sZuxksstfBqdutfxFdkDOHEmrAKxjRR5+1+GA/8VorE=",
			},
		}}))
		replacement := goModulesComponent(fixture, bindings[0].Component)
		gomega.Expect(replacement.Name).To(gomega.Equal(bindings[0].Module.Replace.Path))
		gomega.Expect(replacement.Version).To(gomega.Equal(bindings[0].Module.Replace.Version))
		gomega.Expect(replacement.Source.Checksum).To(gomega.Equal(bindings[0].Module.Replace.Sum))
	})

	ginkgo.It("keeps a directory replacement on the main component without inventing a dependency", func(ctx ginkgo.SpecContext) {
		fixture := goModulesProducerFixture("go-module-local-replaced-elf",
			"sha256:4206d48c818160e69401ce98f6b9e0a614f7db30233c01350eda0459207d90a7",
			"sha256:76c57e02b8499024eab49d19621b6b908bf67e1347be724cfd82f5ac9216f85f")
		libraries, record := goModulesCatalog(ctx, fixture)
		gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "golang": "1.27.3"}))
		bindings := goModulesBindings(record)
		gomega.Expect(bindings).To(gomega.HaveLen(1))
		gomega.Expect(bindings[0]).To(gomega.Equal(shared.GoModuleBinding{Component: "c0", Module: debug.Module{
			Path: "example.com/dep", Version: "v1.2.3", Replace: &debug.Module{Path: "./local", Version: "(devel)"},
		}}))
		gomega.Expect(bindings[0].Component).To(gomega.Equal(fixture.record.Subject))
		main := goModulesComponent(fixture, bindings[0].Component)
		gomega.Expect(main.Name).To(gomega.Equal("sbom.test/app"))
		gomega.Expect(main.Source.Kind).To(gomega.Equal("declared"))
	})

	ginkgo.DescribeTable("retains the recorded VCS build of the main module",
		func(ctx ginkgo.SpecContext, name, bodySHA256, expectedSHA256, mainVersion, modified string) {
			fixture := goModulesProducerFixture(name, bodySHA256, expectedSHA256)
			libraries, record := goModulesCatalog(ctx, fixture)
			gomega.Expect(libraries).To(gomega.Equal(map[string]string{"sbom.test/app": "0.0.1", "example.com/dep": "v1.2.3", "golang": "1.27.3"}))
			gomega.Expect(goModulesBindings(record)).To(gomega.HaveLen(1))
			info, err := buildinfo.Read(bytes.NewReader(fixture.body))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(info.Main.Path).To(gomega.Equal("sbom.test/app"))
			gomega.Expect(info.Main.Version).To(gomega.Equal(mainVersion))
			settings := map[string]string{}
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs", "git"))
			gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.revision", "8ad32f74776330636725aff4ff2bfa48c9c005e1"))
			gomega.Expect(settings).To(gomega.HaveKeyWithValue("vcs.modified", modified))
			gomega.Expect(settings).To(gomega.HaveKeyWithValue("CGO_ENABLED", "0"))
		},
		ginkgo.Entry("tagged", "go-module-vcs-tagged-elf",
			"sha256:7e7c6cbf4c1d14f3ab058aad4a8fbd9a878ca9cb654ee521de5ae4e8aec50778",
			"sha256:0b690898633672e3fb2e5a5af511de5d237aee375cbc5affbd1328463c78b4bc", "v1.2.3", "false"),
		ginkgo.Entry("dirty", "go-module-vcs-dirty-elf",
			"sha256:24f2dd1c4679b57294eae480d62264995837f5f8f18261b43da16a37822d6564",
			"sha256:9d2c59b89d89b7c8ce12e53f0aa63ec3700494a966a278738733cf7d56ca4b6f", "v1.2.3+dirty", "true"),
	)

	ginkgo.It("rejects a buildinfo dependency version that contradicts the recorded mapping", func(ctx ginkgo.SpecContext) {
		fixture := goModulesProducerFixture("go-module-versioned-elf",
			"sha256:309bc007183399cca557943000b2e1e5f1a66557c829485235ea7dc4a166faa7",
			"sha256:eec2cd68a8fb4e8225d38d8a61f59bb8525183037adebec07489290615bed488")
		file, err := elf.NewFile(bytes.NewReader(fixture.body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		info := file.Section(".go.buildinfo")
		gomega.Expect(info).NotTo(gomega.BeNil())
		data, err := info.Data()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(file.Close()).To(gomega.Succeed())
		// Only the buildinfo copy of the dependency line moves; the embedded
		// record keeps the recorded v1.2.3 mapping.
		offset := bytes.Index(data, []byte("\ndep\texample.com/dep\tv1.2.3\t"))
		gomega.Expect(offset).To(gomega.BeNumerically(">=", 0))
		copy(fixture.body[info.Offset+uint64(offset):], "\ndep\texample.com/dep\tv9.9.9\t")
		err = Apply(ctx, NewDefaultPolicy(ctx, "app"), "app", fixtureImage(map[string]string{"/app": string(fixture.body)}), nil, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(`invalid: Go buildinfo dependency "example.com/dep" disagrees with recorded module mapping`)))
	})
})
