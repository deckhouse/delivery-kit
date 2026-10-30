package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func TestNativeGate(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Embedded SBOM gate")
}

func fixtureImage(files map[string]string) v1.Image {
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for name, body := range files {
		gomega.Expect(tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: fixtureFileMode(name), Size: int64(len(body))})).To(gomega.Succeed())
		_, err := tw.Write([]byte(body))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(tw.Close()).To(gomega.Succeed())
	layer, err := tarball.LayerFromReader(&buffer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	img, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return img
}

func fixtureCatalog() Catalog {
	c := emptyCatalog()
	ref := "pkg:generic/example@1"
	c.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: "example", Version: "1", PackageURL: ref}
	c.Records = []Record{{Path: "/bin/a", SHA256: digest([]byte("package-script")), Components: []string{ref}, Owners: []string{ref}, Origin: "pm"}}
	return c
}

var _ = ginkgo.Describe("strict native inventory", func() {
	ginkgo.It("inventories an unreferenced library without inventing runtime loads", func() {
		app, library := minimalRuntimeELF(elf.ET_EXEC), minimalRuntimeELF(elf.ET_DYN)
		appRef, libraryRef := "pkg:generic/app@1", "pkg:generic/plugin@2"
		catalog := emptyCatalog()
		catalog.Components[appRef] = cdx.Component{Type: cdx.ComponentTypeApplication, BOMRef: appRef, PackageURL: appRef, Name: "app", Version: "1"}
		catalog.Components[libraryRef] = cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: libraryRef, PackageURL: libraryRef, Name: "plugin", Version: "2"}
		catalog.Records = []Record{
			{Path: "/app", SHA256: digest(app), Components: []string{appRef}, Owners: []string{appRef}, Origin: "pm"},
			{Path: "/plugins/plugin.so", SHA256: digest(library), Components: []string{libraryRef}, Owners: []string{libraryRef}, Origin: "pm"},
		}
		inherited := cdx.NewBOM()
		gomega.Expect(catalog.attach(inherited)).To(gomega.Succeed())
		policy := fixturePolicy("image")
		target := cdx.NewBOM()
		img := fixtureImage(map[string]string{"/app": string(app), "/plugins/plugin.so": string(library)})
		gomega.Expect(Apply(context.Background(), policy, "image", img, []*cdx.BOM{inherited}, target)).To(gomega.Succeed())
		data, err := cyclonedxutil.ToJSON(target)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		// The component is written with the whereabouts of the files it was read
		// from, which is what lets an image importing a part of this one place it.
		placed := catalog.Components[libraryRef]
		placed.Evidence = &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/plugins/plugin.so", AdditionalContext: digest(library)},
		}}
		gomega.Expect(*restored.Components).To(gomega.ContainElement(placed))
		edges := map[string][]string{}
		for _, dependency := range *restored.Dependencies {
			edges[dependency.Ref] = *dependency.Dependencies
		}
		gomega.Expect(edges[digest(app)+":/app"]).To(gomega.ContainElement(appRef))
		gomega.Expect(edges[digest(app)+":/app"]).NotTo(gomega.ContainElements(libraryRef, digest(library)+":/plugins/plugin.so"))
		gomega.Expect(edges[digest(library)+":/plugins/plugin.so"]).To(gomega.ContainElement(libraryRef))
		gomega.Expect(string(data)).NotTo(gomega.ContainSubstring("dk:runtimeLoads"))

		ginkgo.By("rejecting missing embedded composition instead of silently dropping a library")
		catalog.Records = catalog.Records[:1]
		gomega.Expect(catalog.attach(inherited)).To(gomega.Succeed())
		bare := bytes.Clone(library)
		offset := bytes.Index(bare, []byte(".note.package"))
		gomega.Expect(offset).To(gomega.BeNumerically(">=", 0))
		copy(bare[offset:], []byte(".gone.package"))
		img = fixtureImage(map[string]string{"/app": string(app), "/plugins/plugin.so": string(bare)})
		gomega.Expect(Apply(context.Background(), policy, "image", img, []*cdx.BOM{inherited}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("/plugins/plugin.so: no-data")))
	})
	ginkgo.It("preserves ownership on rename and drops the last removed component", func() {
		c := fixtureCatalog()
		bom := cdx.NewBOM()
		gomega.Expect(c.attach(bom)).To(gomega.Succeed())
		policy := &Policy{Images: map[string]ImagePolicy{"final": {Role: "final"}}}
		target := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "final", fixtureImage(map[string]string{"/renamed": "package-script"}), []*cdx.BOM{bom}, target)).To(gomega.Succeed())
		gomega.Expect(*target.Components).To(gomega.HaveLen(2))
		gomega.Expect((*target.Components)[0].Name + (*target.Components)[1].Name).To(gomega.ContainSubstring("/renamed"))
		target = cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "final", fixtureImage(map[string]string{}), []*cdx.BOM{bom}, target)).To(gomega.Succeed())
		gomega.Expect(*target.Components).To(gomega.BeEmpty())
	})
	ginkgo.DescribeTable("rejects substitution and missing provenance", func(path, body, expected string) {
		c := fixtureCatalog()
		bom := cdx.NewBOM()
		gomega.Expect(c.attach(bom)).To(gomega.Succeed())
		err := Apply(context.Background(), &Policy{Images: map[string]ImagePolicy{"final": {Role: "final"}}}, "final", fixtureImage(map[string]string{path: body}), []*cdx.BOM{bom}, cdx.NewBOM())
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(expected)))
	}, ginkgo.Entry("same name changed content", "/bin/a", "other", "content changed"), ginkgo.Entry("unknown executable", "/bin/new", "other", "unknown binary"))
	ginkgo.It("rejects identical bytes with different version owners instead of unioning them", func() {
		c := fixtureCatalog()
		second := c.Records[0]
		second.Components = []string{"pkg:generic/example@2"}
		second.Owners = slices.Clone(second.Components)
		c.Records = append(c.Records, second)
		_, err := matching(c, "/renamed", second.SHA256)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("ambiguous content ownership")))
	})
	ginkgo.It("keeps compiler evidence separate from final file ownership", func() {
		c := fixtureCatalog()
		for _, origin := range []string{"sdk", "source", "module"} {
			c.Records[0].Origin = origin
			record, err := matching(c, "/unrelated", c.Records[0].SHA256)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(record).To(gomega.BeNil())
		}
		for _, origin := range []string{"pm", "build"} {
			c.Records[0].Origin = origin
			record, err := matching(c, "/renamed", c.Records[0].SHA256)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(record).NotTo(gomega.BeNil())
		}
	})
	ginkgo.It("resolves package path aliases without replacing original hashes", func() {
		c := fixtureCatalog()
		c.Records[0].Path = "/usr/lib64/lib.a"
		original := c.Records[0].SHA256
		fs := &filesystem{index: &shippedscope.FileIndex{Symlinks: map[string]string{"/usr/lib64": "/usr/lib"}}}
		gomega.Expect(c.resolvePaths(fs)).To(gomega.Succeed())
		gomega.Expect(c.Records[0].Path).To(gomega.Equal("/usr/lib/lib.a"))
		gomega.Expect(c.Records[0].SHA256).To(gomega.Equal(original))
	})
	ginkgo.It("checks original pm version and content hashes", func() {
		hash := digest([]byte("original"))
		index := fmt.Sprintf(`{"example":{"name":"example","version":"1","digest":%q}}`, hash)
		files := fmt.Sprintf(`{"example":{"version":"1","files":{"/bin/a":%q},"symlinks":{}}}`, strings.TrimPrefix(hash, "sha256:"))
		c := emptyCatalog()
		gomega.Expect(c.addPM(context.Background(), map[string][]byte{"/var/lib/pm/container-factory-version": []byte("v-test"), "/var/lib/pm/index.json": []byte(index), "/var/lib/pm/files.json": []byte(files), "/bin/a": []byte("modified")})).To(gomega.Succeed())
		gomega.Expect(c.Records[0].SHA256).To(gomega.Equal(hash))
		_, err := matching(c, "/bin/a", digest([]byte("modified")))
		gomega.Expect(err).To(gomega.HaveOccurred())
		c = emptyCatalog()
		gomega.Expect(c.addPM(context.Background(), map[string][]byte{"/var/lib/pm/container-factory-version": []byte("v-test"), "/var/lib/pm/index.json": []byte(index), "/var/lib/pm/files.json": []byte(strings.Replace(files, `"version":"1"`, `"version":"2"`, 1))})).To(gomega.MatchError(gomega.ContainSubstring("pm version/files mismatch")))
	})
	ginkgo.It("terminates cycles while checking transitive SONAME conflicts", func() {
		edges := map[string][]string{"app": {"a"}, "a": {"b"}, "b": {"a", "c"}}
		sonames := map[string][]string{"a": {"liba.so"}, "b": {"libb.so"}, "c": {"libc.so"}}
		gomega.Expect(rejectConflictingRuntimeSONAMEs(edges, sonames, []string{"app"})).To(gomega.Succeed())
		sonames["c"] = []string{"liba.so"}
		gomega.Expect(rejectConflictingRuntimeSONAMEs(edges, sonames, []string{"app"})).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME liba.so")))
	})
	ginkgo.It("requires explicit policy when consuming inherited coownership", func() {
		c := fixtureCatalog()
		other := c.Components["pkg:generic/example@1"]
		other.Name = "other"
		other.PackageURL = "pkg:generic/other@1"
		other.BOMRef = other.PackageURL
		c.Components[other.BOMRef] = other
		c.Records[0].Namespace = "current"
		c.Records[0].Components = append(c.Records[0].Components, other.BOMRef)
		c.Records[0].Owners = slices.Clone(c.Records[0].Components)
		inherited := cdx.NewBOM()
		gomega.Expect(c.attach(inherited)).To(gomega.Succeed())
		img := fixtureImage(map[string]string{"/renamed": "package-script"})
		policy := &Policy{PMOverlap: "all-active-exact-path-hash", Images: map[string]ImagePolicy{"final": {Role: "final"}}}
		gomega.Expect(Apply(context.Background(), policy, "final", img, []*cdx.BOM{inherited}, cdx.NewBOM())).To(gomega.Succeed())
		policy.PMOverlap = ""
		gomega.Expect(Apply(context.Background(), policy, "final", img, []*cdx.BOM{inherited}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("coownership requires current policy")))
		c.Records[0].Origin = "build"
		c.Records[0].Profile = "c-static"
		var err error
		c.Records[0].Composition, err = json.Marshal(fixtureBuildRecord(elf.ET_EXEC))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		c.Records[0].PMOverlap = "all-active-exact-path-hash"
		inherited = cdx.NewBOM()
		gomega.Expect(c.attach(inherited)).To(gomega.Succeed())
		gomega.Expect(Apply(context.Background(), policy, "final", img, []*cdx.BOM{inherited}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("coownership requires current policy")))
	})
	ginkgo.It("groups only current pm exact-path/hash coowners", func() {
		hash := digest([]byte("shared"))
		makeCatalog := func() Catalog {
			c := emptyCatalog()
			c.pmSnapshot = "current"
			c.Records = []Record{
				{Path: "/lib/same", SHA256: hash, Components: []string{"a"}, Owners: []string{"a"}, Origin: "pm", Namespace: "current"},
				{Path: "/lib/same", SHA256: hash, Components: []string{"b"}, Owners: []string{"b"}, Origin: "pm", Namespace: "current"},
				{Path: "/other/same", SHA256: hash, Components: []string{"c"}, Owners: []string{"c"}, Origin: "pm", Namespace: "current"},
			}
			return c
		}
		c := makeCatalog()
		gomega.Expect(c.coalescePM()).To(gomega.Succeed())
		var shared *Record
		for _, record := range c.Records {
			if record.Path == "/lib/same" {
				copy := record
				shared = &copy
			}
		}
		gomega.Expect(shared).NotTo(gomega.BeNil())
		gomega.Expect(shared.Components).To(gomega.ConsistOf("a", "b"))
		_, err := matching(c, "/renamed", hash)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("ambiguous content ownership")))
		c = makeCatalog()
		c.Records[1].Namespace = "historical"
		gomega.Expect(c.coalescePM()).To(gomega.MatchError(gomega.ContainSubstring("historical pm")))
		c = makeCatalog()
		c.Records[1].SHA256 = digest([]byte("different"))
		gomega.Expect(c.coalescePM()).To(gomega.MatchError(gomega.ContainSubstring("conflicting active pm")))
	})
	ginkgo.It("rejects unknown metadata versions and properties", func() {
		var m struct {
			Schema string `json:"schema"`
		}
		gomega.Expect(decode([]byte(`{"schema":"dk.build/v2","unexpected":true}`), &m)).NotTo(gomega.Succeed())
		var c Catalog
		gomega.Expect(json.Unmarshal([]byte(`{"schema":"dk.catalog/v1"}`), &c)).To(gomega.Succeed())
		target := emptyCatalog()
		gomega.Expect(target.add(c)).To(gomega.HaveOccurred())
	})
})

var _ = ginkgo.Describe("What a verified document says about where things stand", func() {
	// An image importing a part of this one keeps of its document what occurs at a path
	// the copy carries. Everything the verification writes therefore has to say where
	// it stands: a file component at the file it is, and a package at every file of the
	// image it was read to own.
	ginkgo.It("places every component it writes at the files it was proven from", func() {
		body := []byte("package-script")
		ref := "pkg:generic/example@1"
		catalog := emptyCatalog()
		identity := &[]cdx.EvidenceIdentity{{Field: cdx.EvidenceIdentityFieldTypePURL, Confidence: lo.ToPtr(float32(1))}}
		catalog.Components[ref] = cdx.Component{
			Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: "example", Version: "1", PackageURL: ref,
			Evidence: &cdx.Evidence{Identity: identity},
		}
		catalog.Records = []Record{
			{Path: "/bin/a", SHA256: digest(body), Components: []string{ref}, Owners: []string{ref}, Origin: "pm"},
			{Path: "/bin/b", SHA256: digest(body), Components: []string{ref}, Owners: []string{ref}, Origin: "pm"},
		}
		inherited := cdx.NewBOM()
		gomega.Expect(catalog.attach(inherited)).To(gomega.Succeed())

		target := cdx.NewBOM()
		img := fixtureImage(map[string]string{"/bin/a": string(body), "/bin/b": string(body)})
		gomega.Expect(Apply(context.Background(), fixturePolicy("image"), "image", img, []*cdx.BOM{inherited}, target)).To(gomega.Succeed())

		placed := map[string][]cdx.EvidenceOccurrence{}
		for _, component := range *target.Components {
			gomega.Expect(component.Evidence).NotTo(gomega.BeNil(), component.BOMRef+" states nowhere it stands")
			placed[component.BOMRef] = *component.Evidence.Occurrences
		}
		gomega.Expect(placed[digest(body)+":/bin/a"]).To(gomega.Equal([]cdx.EvidenceOccurrence{
			{Location: "/bin/a", AdditionalContext: digest(body)},
		}), "a file component stands at the file it is")
		gomega.Expect(placed[ref]).To(gomega.Equal([]cdx.EvidenceOccurrence{
			{Location: "/bin/a", AdditionalContext: digest(body)},
			{Location: "/bin/b", AdditionalContext: digest(body)},
		}), "a package stands at every file of it this image holds")

		// Where it stands is this build's to state; whatever else the component's
		// evidence carries is the donor's and is left as it arrived.
		for _, component := range *target.Components {
			if component.BOMRef == ref {
				gomega.Expect(component.Evidence.Identity).To(gomega.Equal(identity))
			}
		}
	})
})
