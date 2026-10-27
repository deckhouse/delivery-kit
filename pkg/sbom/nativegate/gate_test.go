package nativegate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
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
		ins := inspector{catalog: &c, fs: fs}
		refs, err := ins.input(Source{Path: "/usr/lib/lib.a", SHA256: original})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(refs).To(gomega.Equal(c.Records[0].Components))
		_, err = ins.input(Source{Path: "/usr/lib/lib.a", SHA256: digest([]byte("changed"))})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("unknown native input")))
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
	ginkgo.It("checks the selected archive member against original package bytes", func() {
		member := []byte("object bytes")
		body := []byte("!<arch>\n" + fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", "a.o/", 0, 0, 0, "644", len(member)))
		body = append(body, member...)
		if len(body)%2 != 0 {
			body = append(body, '\n')
		}
		whole := digest(body)
		ins := inspector{image: ImagePolicy{MetaDir: "/meta"}, archives: map[string][]byte{"/meta/archives/" + strings.TrimPrefix(whole, "sha256:") + ".a": body}}
		input := LinkInput{Archive: &Source{Path: "/lib/a.a", SHA256: whole}, Member: "a.o", SHA256: digest(member)}
		gomega.Expect(ins.archiveMember(input)).To(gomega.Succeed())
		input.SHA256 = digest([]byte("other"))
		gomega.Expect(ins.archiveMember(input)).To(gomega.MatchError(gomega.ContainSubstring("member content mismatch")))
	})
	ginkgo.It("verifies SDK sources against the pinned distribution archive", func() {
		var buffer bytes.Buffer
		gz := gzip.NewWriter(&buffer)
		tw := tar.NewWriter(gz)
		source := []byte("sdk source")
		gomega.Expect(tw.WriteHeader(&tar.Header{Name: "sdk/src/a.c", Mode: 0o644, Size: int64(len(source))})).To(gomega.Succeed())
		_, err := tw.Write(source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(tw.Close()).To(gomega.Succeed())
		gomega.Expect(gz.Close()).To(gomega.Succeed())
		dist := Distribution{URL: "https://example.invalid/sdk.tar.gz", SHA256: digest(buffer.Bytes())}
		comp := fixtureCatalog().Components["pkg:generic/example@1"]
		inventory := map[string]any{"schema": "dk.sources/v2", "distribution": dist, "components": []cdx.Component{comp}, "files": []map[string]string{{"path": "/opt/sdk/src/a.c", "sha256": digest(source), "component": comp.BOMRef, "archivePath": "sdk/src/a.c"}}}
		raw, err := json.Marshal(inventory)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		bodies := map[string][]byte{"/meta/sources.json": raw, "/meta/distributions/" + strings.TrimPrefix(dist.SHA256, "sha256:") + ".tar.gz": buffer.Bytes()}
		policy := &Policy{Distributions: []Distribution{dist}}
		c := emptyCatalog()
		gomega.Expect(c.addDistributions(policy, ImagePolicy{MetaDir: "/meta"}, bodies)).To(gomega.Succeed())
		gomega.Expect(c.Records[0].SHA256).To(gomega.Equal(digest(source)))
		bodies["/meta/sources.json"] = bytes.ReplaceAll(raw, []byte(digest(source)), []byte(digest([]byte("wrong"))))
		c = emptyCatalog()
		gomega.Expect(c.addDistributions(policy, ImagePolicy{MetaDir: "/meta"}, bodies)).To(gomega.MatchError(gomega.ContainSubstring("SDK source/member mismatch")))
		bodies["/meta/sources.json"] = raw
		c = emptyCatalog()
		gomega.Expect(c.addDistributions(&Policy{}, ImagePolicy{MetaDir: "/meta"}, bodies)).To(gomega.MatchError(gomega.ContainSubstring("unknown SDK distribution")))
	})
	ginkgo.It("derives source ownership from Git layers and rejects prebuilt or vendor content", func() {
		ranges := shippedscope.ProducedLayers{Known: true, Ranges: []shippedscope.ProducedLayerRange{{Start: 0, End: 1}}}
		ctx := context.Background()
		sources, err := ProjectSources(ctx, fixtureImage(map[string]string{"/src/main.c": "int main(void){return 0;}"}), ranges)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(sources["/src/main.c"]).To(gomega.Equal(digest([]byte("int main(void){return 0;}"))))
		_, err = ProjectSources(ctx, fixtureImage(map[string]string{"/src/prebuilt": "\x7fELFknown package bytes"}), ranges)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("prebuilt binary in Git")))
		_, err = ProjectSources(ctx, fixtureImage(map[string]string{"/src/vendor/lib/a.c": "source"}), ranges)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("vendored path in Git")))
	})
	ginkgo.It("rejects generic own assembly until assembler dependencies are traced", func() {
		c := fixtureCatalog()
		h := digest([]byte("object"))
		src := Source{Path: "/src/raw.S", SHA256: digest([]byte("assembly"))}
		tool := Tool{Name: "cc", Version: "1", SHA256: digest([]byte("cc"))}
		ins := inspector{policy: &Policy{Tools: []Tool{tool}}, image: ImagePolicy{Sources: map[string]string{src.Path: src.SHA256}}, catalog: &c, active: map[string]bool{}, compiled: map[string]Compile{h: {Schema: "dk.compile/v2", SHA256: h, Tool: tool, Language: "asm", Sources: []Source{src}}}}
		record := ins.compiled[h]
		record.Language = "go"
		ins.compiled[h] = record
		_, err := ins.input(Source{Path: "/raw.o", SHA256: h})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("own-source assembly dependency tracing unsupported")))
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
