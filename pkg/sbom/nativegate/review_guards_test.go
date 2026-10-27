package nativegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func loaderFixture() map[string][]byte {
	dir := os.Getenv("DK_LOADER_FIXTURE")
	if dir == "" {
		ginkgo.Skip("run loader-oracle-v3.py and set DK_LOADER_FIXTURE for pinned Linux loader regression")
	}
	files := map[string][]byte{}
	for _, name := range []string{"app", "app-rpath", "v1/libpick.so.1", "v2/libpick.so.1", "other/libpick.so.1", "ld-linux-x86-64.so.2", "libc.so.6"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files[name] = body
	}
	gomega.Expect(digest(files["ld-linux-x86-64.so.2"])).To(gomega.Equal(supportedRuntimeLoaderSHA256))
	return files
}

func runtimeFixture(files map[string][]byte, app string, layout map[string]string) (*filesystem, map[string]Record) {
	fs := &filesystem{index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}}, bodies: map[string][]byte{}}
	present := map[string]Record{}
	entries := map[string]string{"/app": app, "/lib64/ld-linux-x86-64.so.2": "ld-linux-x86-64.so.2", "/lib64/libc.so.6": "libc.so.6"}
	for name, file := range layout {
		entries[name] = file
	}
	for name, file := range entries {
		body := files[file]
		fs.bodies[name] = body
		fs.index.Files[name] = shippedscope.File{Digest: digest(body)}
		present[name] = Record{Path: name, SHA256: digest(body), Origin: "pm", Components: []string{file}}
	}
	return fs, present
}

var _ = ginkgo.Describe("independent review regressions", func() {
	ginkgo.It("rejects conflicting SONAME owners per executable closure", func() {
		files := loaderFixture()
		for _, name := range []string{"app", "app2", "app-direct", "x/libmid.so.1", "v1/libpick.so.1", "v2/libpick.so.1"} {
			body, err := os.ReadFile(filepath.Join(os.Getenv("DK_LOADER_FIXTURE"), "reuse", name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			files["reuse/"+name] = body
		}
		gomega.Expect(digest(files["reuse/app"])).To(gomega.Equal("sha256:382dc401f824070bd526a48e8557ff704dfc4b8e331b9b866c2cdf7b430e107b"))
		layout := map[string]string{"/opt/x/libmid.so.1": "reuse/x/libmid.so.1", "/opt/x/libpick.so.1": "reuse/v1/libpick.so.1", "/lib64/libpick.so.1": "reuse/v2/libpick.so.1"}
		fs, present := runtimeFixture(files, "reuse/app", layout)
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME libpick.so.1 in closure of /app")))

		ginkgo.By("keeping independent executables in separate namespaces")
		fs, present = runtimeFixture(files, "reuse/app2", map[string]string{"/lib64/libpick.so.1": "reuse/v2/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.Succeed())
		delete(layout, "/opt/x/libmid.so.1")
		layout["/app2"] = "reuse/app2"
		fs, present = runtimeFixture(files, "reuse/app-direct", layout)
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.Succeed())
		gomega.Expect(present["/app"].Components).To(gomega.ContainElement("reuse/v1/libpick.so.1"))
		gomega.Expect(present["/app"].Components).NotTo(gomega.ContainElement("reuse/v2/libpick.so.1"))
		gomega.Expect(present["/app2"].Components).To(gomega.ContainElement("reuse/v2/libpick.so.1"))
		gomega.Expect(present["/app2"].Components).NotTo(gomega.ContainElement("reuse/v1/libpick.so.1"))

		ginkgo.By("conservatively rejecting equal bytes at different owner paths")
		delete(layout, "/app2")
		layout["/opt/x/libmid.so.1"] = "reuse/x/libmid.so.1"
		layout["/lib64/libpick.so.1"] = "reuse/v1/libpick.so.1"
		fs, present = runtimeFixture(files, "reuse/app", layout)
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME")))

		ginkgo.By("checking static executable runtime declarations and terminating cycles")
		nativeDir := os.Getenv("DK_NATIVE_INSPECT_FIXTURE")
		if nativeDir == "" {
			ginkgo.Skip("DK_NATIVE_INSPECT_FIXTURE required for static runtime declaration regression")
		}
		body, err := os.ReadFile(filepath.Join(nativeDir, "app"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files["static"] = body
		delete(layout, "/opt/x/libmid.so.1")
		layout["/lib64/libpick.so.1"] = "reuse/v2/libpick.so.1"
		fs, present = runtimeFixture(files, "static", layout)
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.Succeed())
		gomega.Expect(dynamicClosure(fs, present, []string{"/opt/x/libpick.so.1", "/lib64/libpick.so.1"})).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME libpick.so.1 in closure of /app")))
	})
	ginkgo.It("matches pinned loader default paths and rejects a different loader", func() {
		files := loaderFixture()
		fs, present := runtimeFixture(files, "app", map[string]string{"/lib/libpick.so.1": "v1/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("missing runtime dependency libpick.so.1")))
		fs, present = runtimeFixture(files, "app", map[string]string{"/lib/libpick.so.1": "v1/libpick.so.1", "/usr/lib64/libpick.so.1": "v2/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.Succeed())
		gomega.Expect(present["/app"].Components).To(gomega.ContainElement("v2/libpick.so.1"))
		gomega.Expect(present["/app"].Components).NotTo(gomega.ContainElement("v1/libpick.so.1"))
		fs, present = runtimeFixture(files, "app", map[string]string{"/lib64/libpick.so.1": "v1/libpick.so.1", "/usr/lib64/libpick.so.1": "v2/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.Succeed())
		gomega.Expect(present["/app"].Components).To(gomega.ContainElement("v1/libpick.so.1"))
		gomega.Expect(present["/app"].Components).NotTo(gomega.ContainElement("v2/libpick.so.1"))
		fs.bodies["/lib64/ld-linux-x86-64.so.2"] = append(bytes.Clone(files["ld-linux-x86-64.so.2"]), 0)
		r := present["/lib64/ld-linux-x86-64.so.2"]
		r.SHA256 = digest(fs.bodies[r.Path])
		present[r.Path] = r
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("unsupported or unknown runtime loader")))
	})
	ginkgo.It("rejects unmodelled loader features and mismatched SONAME", func() {
		files := loaderFixture()
		for _, feature := range []string{"/etc/ld.so.cache", "/etc/ld.so.preload", "/lib64/glibc-hwcaps/x86-64-v3/libpick.so.1"} {
			fs, present := runtimeFixture(files, "app", map[string]string{"/lib64/libpick.so.1": "v1/libpick.so.1"})
			fs.index.Files[feature] = shippedscope.File{}
			gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader feature")))
		}
		fs, present := runtimeFixture(files, "app", map[string]string{"/lib64/libpick.so.1": "v1/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, nil)).To(gomega.MatchError(gomega.ContainSubstring("runtimeLoads declaration required")))
		fs, present = runtimeFixture(files, "app-rpath", map[string]string{"/lib64/libpick.so.1": "v1/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("DT_RPATH inheritance unsupported")))
		fs, present = runtimeFixture(files, "app", map[string]string{"/lib64/libpick.so.1": "other/libpick.so.1"})
		gomega.Expect(dynamicClosure(fs, present, []string{})).To(gomega.MatchError(gomega.ContainSubstring("runtime SONAME mismatch")))
	})
	ginkgo.It("rejects runtime environment overrides through Apply", func() {
		for _, name := range []string{"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"} {
			img := fixtureImage(map[string]string{})
			cfg, err := img.ConfigFile()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			cfg.Config.Env = []string{name + "=/foreign"}
			img, err = mutate.ConfigFile(img, cfg)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			policy := &Policy{Images: map[string]ImagePolicy{"final": {Role: "final", RuntimeLoads: []string{}}}}
			gomega.Expect(Apply(context.Background(), policy, "final", img, nil, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader environment")))
		}
	})
	ginkgo.It("pins name version and content of tools", func() {
		known := Tool{Name: "cc", Version: "1", SHA256: digest([]byte("compiler"))}
		policy := &Policy{Tools: []Tool{known}}
		gomega.Expect(policy.checkTool(known)).To(gomega.Succeed())
		for _, changed := range []Tool{{Name: "other", Version: known.Version, SHA256: known.SHA256}, {Name: known.Name, Version: "2", SHA256: known.SHA256}, {Name: known.Name, Version: known.Version, SHA256: digest([]byte("other compiler"))}} {
			gomega.Expect(policy.checkTool(changed)).To(gomega.MatchError(gomega.ContainSubstring("unregistered tool")))
		}
	})
	ginkgo.It("captures pm release identity and rejects a missing version", func() {
		hash := digest([]byte("package"))
		index := fmt.Sprintf(`{"example":{"name":"example","version":"1","digest":%q}}`, hash)
		files := fmt.Sprintf(`{"example":{"version":"1","files":{"/bin/a":%q},"symlinks":{}}}`, hash)
		bodies := map[string]string{"/var/lib/pm/index.json": index, "/var/lib/pm/files.json": files, "/var/lib/pm/container-factory-version": "v3.1.16\n"}
		policy := &Policy{Images: map[string]ImagePolicy{"producer": {Role: "produce", MetaDir: "/meta"}}}
		bom := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "producer", fixtureImage(bodies), nil, bom)).To(gomega.Succeed())
		var catalog Catalog
		for _, p := range *bom.Metadata.Properties {
			if p.Name == catalogProperty {
				gomega.Expect(json.Unmarshal([]byte(p.Value), &catalog)).To(gomega.Succeed())
			}
		}
		gomega.Expect(catalog.Components).To(gomega.HaveKey("pkg:generic/example@1?containerfactoryversion=v3.1.16"))
		delete(bodies, "/var/lib/pm/container-factory-version")
		gomega.Expect(Apply(context.Background(), policy, "producer", fixtureImage(bodies), nil, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("missing pm container-factory version")))
	})
	ginkgo.It("rejects inherited legacy empty package release qualifiers", func() {
		ref := "pkg:generic/example@1?containerfactoryversion="
		old := emptyCatalog()
		old.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "example", Version: "1", PackageURL: ref, BOMRef: ref}
		bom := cdx.NewBOM()
		gomega.Expect(old.attach(bom)).To(gomega.Succeed())
		policy := &Policy{Images: map[string]ImagePolicy{"final": {Role: "final", RuntimeLoads: []string{}}}}
		gomega.Expect(Apply(context.Background(), policy, "final", fixtureImage(map[string]string{}), []*cdx.BOM{bom}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("incomplete catalog component")))
	})
	ginkgo.It("requires current overlap opt-in inside compiler source inspection", func() {
		c := fixtureCatalog()
		c.Records[0].Namespace = "current"
		c.Records[0].Components = []string{"a", "b"}
		ins := inspector{policy: &Policy{PMOverlap: "all-active-exact-path-hash"}, catalog: &c}
		source := Source{Path: c.Records[0].Path, SHA256: c.Records[0].SHA256}
		refs, err := ins.source(source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(refs).To(gomega.ConsistOf("a", "b"))
		ins.policy.PMOverlap = ""
		_, err = ins.source(source)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("pm coownership requires current policy opt-in")))
	})
	ginkgo.It("rejects compiler records whose filenames disagree with output hashes", func() {
		record := Compile{Schema: "dk.compile/v2", SHA256: digest([]byte("object"))}
		raw, err := json.Marshal(record)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		policy := &Policy{Images: map[string]ImagePolicy{"producer": {Role: "produce", MetaDir: "/meta"}}}
		correct := "/meta/objects/" + strings.TrimPrefix(record.SHA256, "sha256:") + ".json"
		gomega.Expect(Apply(context.Background(), policy, "producer", fixtureImage(map[string]string{correct: string(raw)}), nil, cdx.NewBOM())).To(gomega.Succeed())
		gomega.Expect(Apply(context.Background(), policy, "producer", fixtureImage(map[string]string{"/meta/objects/wrong.json": string(raw)}), nil, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("compiler record filename/hash mismatch")))
	})
})
