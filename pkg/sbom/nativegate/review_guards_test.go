package nativegate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
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
	return files
}

// fixtureLoaderDirs are the directories the fixture's own loader was built to search.
// They are read out of it rather than assumed, so a fixture captured on one distribution
// does not have to be re-captured to describe another.
func fixtureLoaderDirs(files map[string][]byte) []string {
	ginkgo.GinkgoHelper()
	model, err := readLoaderModel(files["ld-linux-x86-64.so.2"], "/lib64/ld-linux-x86-64.so.2")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return model.dirs
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
		present[name] = Record{Path: name, SHA256: digest(body), Origin: "pm", Components: []string{file}, Owners: []string{file}}
	}
	return fs, present
}

var _ = ginkgo.Describe("independent review regressions", func() {
	ginkgo.It("serializes direct runtime file edges without claiming programmatic loading", func() {
		files := loaderFixture()
		fs, present := runtimeFixture(files, "app", map[string]string{"/lib64/libpick.so.1": "v1/libpick.so.1", "/opt/plugin.so": "v2/libpick.so.1"})
		catalog := emptyCatalog()
		imageFiles := map[string]string{}
		for name, record := range present {
			ref := "pkg:generic/runtime@" + strings.TrimPrefix(record.SHA256, "sha256:")
			record.Components = []string{ref}
			record.Owners = []string{ref}
			catalog.Records = append(catalog.Records, record)
			present[name] = record
			catalog.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "runtime", Version: strings.TrimPrefix(record.SHA256, "sha256:"), PackageURL: ref, BOMRef: ref}
			imageFiles[name] = string(fs.bodies[name])
		}
		inherited := cdx.NewBOM()
		gomega.Expect(catalog.attach(inherited)).To(gomega.Succeed())
		target := cdx.NewBOM()
		policy := &Policy{Images: map[string]ImagePolicy{"image": {Role: "final"}}}
		ginkgo.By("requiring embedded metadata even when an original package hash is known")
		gomega.Expect(Apply(context.Background(), policy, "image", fixtureImage(imageFiles), []*cdx.BOM{inherited}, target)).To(gomega.MatchError(gomega.ContainSubstring("no-data")))
		runtimeEdges, err := runtimeDependencies(fs, present)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(catalog.writeBOM(present, runtimeEdges, target)).To(gomega.Succeed())
		data, err := cyclonedxutil.ToJSON(target)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		restored, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		edges := map[string][]string{}
		for _, dependency := range *restored.Dependencies {
			edges[dependency.Ref] = *dependency.Dependencies
		}
		fileRef := func(name string) string { return present[name].SHA256 + ":" + name }
		gomega.Expect(edges[fileRef("/app")]).To(gomega.ContainElements(fileRef("/lib64/libpick.so.1"), fileRef("/lib64/ld-linux-x86-64.so.2")))
		gomega.Expect(edges[fileRef("/app")]).NotTo(gomega.ContainElement(fileRef("/opt/plugin.so")))
		gomega.Expect(edges).To(gomega.HaveKey(fileRef("/opt/plugin.so")))
		gomega.Expect(edges[fileRef("/lib64/libpick.so.1")]).NotTo(gomega.ContainElement(fileRef("/app")))
	})
	ginkgo.It("rejects conflicting SONAME owners per executable closure", func() {
		files := loaderFixture()
		for _, name := range []string{"app", "app2", "app-direct", "app-pie", "app-nosoname", "nosoname/libpick.so.1", "x/libmid.so.1", "v1/libpick.so.1", "v2/libpick.so.1"} {
			body, err := os.ReadFile(filepath.Join(os.Getenv("DK_LOADER_FIXTURE"), "reuse", name))
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			files["reuse/"+name] = body
		}
		gomega.Expect(digest(files["reuse/app"])).To(gomega.Equal("sha256:382dc401f824070bd526a48e8557ff704dfc4b8e331b9b866c2cdf7b430e107b"))
		layout := map[string]string{"/opt/x/libmid.so.1": "reuse/x/libmid.so.1", "/opt/x/libpick.so.1": "reuse/v1/libpick.so.1", "/lib64/libpick.so.1": "reuse/v2/libpick.so.1"}
		fs, present := runtimeFixture(files, "reuse/app", layout)
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME libpick.so.1 in closure of /app")))

		ginkgo.By("registering PIE executables through PT_INTERP")
		pie, err := elf.NewFile(bytes.NewReader(files["reuse/app-pie"]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(pie.Type).To(gomega.Equal(elf.ET_DYN))
		hasInterpreter := false
		for _, program := range pie.Progs {
			hasInterpreter = hasInterpreter || program.Type == elf.PT_INTERP
		}
		gomega.Expect(pie.Close()).To(gomega.Succeed())
		gomega.Expect(hasInterpreter).To(gomega.BeTrue())
		fs, present = runtimeFixture(files, "reuse/app-pie", layout)
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME libpick.so.1 in closure of /app")))

		ginkgo.By("rejecting basename NEEDED when the DSO has no SONAME")
		dso, err := elf.NewFile(bytes.NewReader(files["reuse/nosoname/libpick.so.1"]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		names, err := dso.DynString(elf.DT_SONAME)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(names).To(gomega.BeEmpty())
		gomega.Expect(dso.Close()).To(gomega.Succeed())
		nativeApp, err := elf.NewFile(bytes.NewReader(files["reuse/app-nosoname"]))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		needed, err := nativeApp.ImportedLibraries()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(needed).To(gomega.ContainElement("libpick.so.1"))
		gomega.Expect(nativeApp.Close()).To(gomega.Succeed())
		fs, present = runtimeFixture(files, "reuse/app-nosoname", map[string]string{"/lib64/libpick.so.1": "reuse/nosoname/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("runtime SONAME mismatch /lib64/libpick.so.1")))

		ginkgo.By("keeping independent executables in separate namespaces")
		fs, present = runtimeFixture(files, "reuse/app2", map[string]string{"/lib64/libpick.so.1": "reuse/v2/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.Succeed())
		delete(layout, "/opt/x/libmid.so.1")
		layout["/app2"] = "reuse/app2"
		fs, present = runtimeFixture(files, "reuse/app-direct", layout)
		gomega.Expect(runtimeError(fs, present)).To(gomega.Succeed())
		gomega.Expect(runtimeTargets(fs, present, "/app")).To(gomega.ContainElement("/opt/x/libpick.so.1"))
		gomega.Expect(runtimeTargets(fs, present, "/app")).NotTo(gomega.ContainElement("/lib64/libpick.so.1"))
		gomega.Expect(runtimeTargets(fs, present, "/app2")).To(gomega.ContainElement("/lib64/libpick.so.1"))
		gomega.Expect(runtimeTargets(fs, present, "/app2")).NotTo(gomega.ContainElement("/opt/x/libpick.so.1"))

		ginkgo.By("conservatively rejecting equal bytes at different owner paths")
		delete(layout, "/app2")
		layout["/opt/x/libmid.so.1"] = "reuse/x/libmid.so.1"
		layout["/lib64/libpick.so.1"] = "reuse/v1/libpick.so.1"
		fs, present = runtimeFixture(files, "reuse/app", layout)
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("conflicting runtime SONAME")))

		ginkgo.By("keeping unrelated libraries out of a static executable closure")
		nativeDir := os.Getenv("DK_NATIVE_INSPECT_FIXTURE")
		if nativeDir == "" {
			ginkgo.Skip("DK_NATIVE_INSPECT_FIXTURE required for static runtime inventory regression")
		}
		body, err := os.ReadFile(filepath.Join(nativeDir, "app"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files["static"] = body
		delete(layout, "/opt/x/libmid.so.1")
		layout["/lib64/libpick.so.1"] = "reuse/v2/libpick.so.1"
		fs, present = runtimeFixture(files, "static", layout)
		gomega.Expect(runtimeError(fs, present)).To(gomega.Succeed())
		gomega.Expect(runtimeTargets(fs, present, "/app")).To(gomega.BeEmpty())
		gomega.Expect(present).To(gomega.HaveKey("/opt/x/libpick.so.1"))
		gomega.Expect(present).To(gomega.HaveKey("/lib64/libpick.so.1"))
	})
	ginkgo.It("searches the directories its own loader was built with, in order", func() {
		files := loaderFixture()
		dirs := fixtureLoaderDirs(files)
		if len(dirs) < 2 {
			ginkgo.Skip("the pinned loader searches one directory; order needs two")
		}
		// A directory this loader does not search does not answer a name.
		fs, present := runtimeFixture(files, "app", map[string]string{"/opt/unsearched/libpick.so.1": "v1/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("missing runtime dependency libpick.so.1")))

		// Of the directories it does search, the earlier one answers first.
		first, second := dirs[0]+"/libpick.so.1", dirs[1]+"/libpick.so.1"
		fs, present = runtimeFixture(files, "app", map[string]string{second: "v2/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.Succeed())
		gomega.Expect(runtimeTargets(fs, present, "/app")).To(gomega.ContainElement(second))

		fs, present = runtimeFixture(files, "app", map[string]string{first: "v1/libpick.so.1", second: "v2/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.Succeed())
		gomega.Expect(runtimeTargets(fs, present, "/app")).To(gomega.ContainElement(first))
		gomega.Expect(runtimeTargets(fs, present, "/app")).NotTo(gomega.ContainElement(second))
	})

	ginkgo.It("refuses a loader whose bytes are not the ones its record describes", func() {
		files := loaderFixture()
		dirs := fixtureLoaderDirs(files)
		fs, present := runtimeFixture(files, "app", map[string]string{dirs[0] + "/libpick.so.1": "v1/libpick.so.1"})
		fs.bodies["/lib64/ld-linux-x86-64.so.2"] = append(bytes.Clone(files["ld-linux-x86-64.so.2"]), 0)

		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring(
			"hash-mismatch: the runtime loader /lib64/ld-linux-x86-64.so.2 is not the file its record describes")))
	})

	ginkgo.It("refuses a loader this build accounts for in no way at all", func() {
		files := loaderFixture()
		dirs := fixtureLoaderDirs(files)
		fs, present := runtimeFixture(files, "app", map[string]string{dirs[0] + "/libpick.so.1": "v1/libpick.so.1"})
		delete(present, "/lib64/ld-linux-x86-64.so.2")

		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring(
			"unknown runtime loader /lib64/ld-linux-x86-64.so.2")))
	})
	ginkgo.It("rejects unmodelled loader features and mismatched SONAME", func() {
		files := loaderFixture()
		dirs := fixtureLoaderDirs(files)
		held := dirs[0] + "/libpick.so.1"
		model, err := readLoaderModel(files["ld-linux-x86-64.so.2"], "/lib64/ld-linux-x86-64.so.2")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, feature := range []string{model.cache, "/etc/ld.so.preload", dirs[0] + "/glibc-hwcaps/x86-64-v3/libpick.so.1"} {
			fs, present := runtimeFixture(files, "app", map[string]string{held: "v1/libpick.so.1"})
			fs.index.Files[feature] = shippedscope.File{}
			gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("unsupported dynamic loader feature")), feature)
		}
		fs, present := runtimeFixture(files, "app-rpath", map[string]string{held: "v1/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("DT_RPATH inheritance unsupported")))
		fs, present = runtimeFixture(files, "app", map[string]string{held: "other/libpick.so.1"})
		gomega.Expect(runtimeError(fs, present)).To(gomega.MatchError(gomega.ContainSubstring("runtime SONAME mismatch")))
	})
	ginkgo.It("rejects runtime environment overrides through Apply", func() {
		for _, name := range []string{"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"} {
			img := fixtureImage(map[string]string{})
			cfg, err := img.ConfigFile()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			cfg.Config.Env = []string{name + "=/foreign"}
			img, err = mutate.ConfigFile(img, cfg)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			policy := &Policy{Images: map[string]ImagePolicy{"final": {Role: "final"}}}
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
		body := minimalRuntimeELF(elf.ET_EXEC)
		hash := digest(body)
		index := fmt.Sprintf(`{"example":{"name":"example","version":"1","digest":%q}}`, hash)
		files := fmt.Sprintf(`{"example":{"version":"1","files":{"/bin/a":%q},"symlinks":{}}}`, hash)
		bodies := map[string]string{"/bin/a": string(body), "/var/lib/pm/index.json": index, "/var/lib/pm/files.json": files, "/var/lib/pm/container-factory-version": "v3.1.16\n"}
		policy := fixturePolicy("producer")
		policy.Images["producer"] = ImagePolicy{Role: "produce", Outputs: []string{"/bin/a"}}

		bom := cdx.NewBOM()
		gomega.Expect(Apply(context.Background(), policy, "producer", fixtureImage(bodies), nil, bom)).To(gomega.Succeed())
		var catalog Catalog
		for _, p := range *bom.Metadata.Properties {
			if p.Name == CatalogProperty {
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
		policy := &Policy{Images: map[string]ImagePolicy{"final": {Role: "final"}}}
		gomega.Expect(Apply(context.Background(), policy, "final", fixtureImage(map[string]string{}), []*cdx.BOM{bom}, cdx.NewBOM())).To(gomega.MatchError(gomega.ContainSubstring("incomplete catalog component")))
	})
})
