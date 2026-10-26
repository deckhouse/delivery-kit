package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestNativeGate(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Native gate v2")
}

func fixtureImage(files map[string]string) v1.Image {
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for name, body := range files {
		gomega.Expect(tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(name, "/"), Mode: 0o755, Size: int64(len(body))})).To(gomega.Succeed())
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
	c.Records = []Record{{Path: "/bin/a", SHA256: digest([]byte("package-script")), Components: []string{ref}, Origin: "pm"}}
	return c
}

var _ = ginkgo.Describe("strict native inventory", func() {
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
		c.Records = append(c.Records, second)
		_, err := matching(c, "/renamed", second.SHA256)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("ambiguous content ownership")))
	})
	ginkgo.It("checks original pm version and content hashes", func() {
		hash := digest([]byte("original"))
		index := fmt.Sprintf(`{"example":{"name":"example","version":"1","digest":%q}}`, hash)
		files := fmt.Sprintf(`{"example":{"version":"1","files":{"/bin/a":%q},"symlinks":{}}}`, strings.TrimPrefix(hash, "sha256:"))
		c := emptyCatalog()
		gomega.Expect(c.addPM(context.Background(), map[string][]byte{"/var/lib/pm/index.json": []byte(index), "/var/lib/pm/files.json": []byte(files), "/bin/a": []byte("modified")})).To(gomega.Succeed())
		gomega.Expect(c.Records[0].SHA256).To(gomega.Equal(hash))
		_, err := matching(c, "/bin/a", digest([]byte("modified")))
		gomega.Expect(err).To(gomega.HaveOccurred())
		c = emptyCatalog()
		gomega.Expect(c.addPM(context.Background(), map[string][]byte{"/var/lib/pm/index.json": []byte(index), "/var/lib/pm/files.json": []byte(strings.Replace(files, `"version":"1"`, `"version":"2"`, 1))})).To(gomega.MatchError(gomega.ContainSubstring("pm version/files mismatch")))
	})
	ginkgo.It("requires known sources behind a content-addressed compiler record", func() {
		c := fixtureCatalog()
		h := digest([]byte("object"))
		tool := Tool{Name: "cc", Version: "1", SHA256: digest([]byte("cc"))}
		ins := inspector{policy: &Policy{Tools: []Tool{tool}}, catalog: &c, active: map[string]bool{}, compiled: map[string]Compile{h: {Schema: "dk.compile/v2", SHA256: h, Tool: tool, Language: "c", Sources: []Source{{Path: "/unknown.c", SHA256: digest([]byte("source"))}}}}}
		_, err := ins.input(Source{Path: "/new.o", SHA256: h})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unknown/ambiguous source")))
		r := ins.compiled[h]
		r.Sources = nil
		r.Inputs = []Source{{Path: "/new.o", SHA256: h}}
		ins.compiled[h] = r
		_, err = ins.input(Source{Path: "/new.o", SHA256: h})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("cyclic")))
	})
	ginkgo.It("computes transitive closure independent of map order and tolerates runtime cycles", func() {
		for n := 0; n < 32; n++ {
			p := map[string]Record{"A": {Components: []string{"a"}}, "B": {Components: []string{"b"}}, "C": {Components: []string{"c"}}}
			closeComponents(p, map[string][]string{"A": {"B"}, "B": {"C"}, "C": {"B"}})
			gomega.Expect(p["A"].Components).To(gomega.Equal([]string{"a", "b", "c"}))
			gomega.Expect(p["B"].Components).To(gomega.Equal([]string{"b", "c"}))
		}
	})
	ginkgo.It("rejects unknown metadata versions and properties", func() {
		var m Method
		gomega.Expect(decode([]byte(`{"schema":"dk.build/v2","unexpected":true}`), &m)).NotTo(gomega.Succeed())
		var c Catalog
		gomega.Expect(json.Unmarshal([]byte(`{"schema":"dk.catalog/v1"}`), &c)).To(gomega.Succeed())
		target := emptyCatalog()
		gomega.Expect(target.add(c)).To(gomega.HaveOccurred())
	})
})
