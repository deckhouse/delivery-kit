package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/docker_registry"
	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

const (
	// The one pm build this smoke runs; nothing here builds or installs a pm.
	pmSmokeBinarySHA256 = "sha256:d40ad4f58374fe296d367ef6b144d08fa49f2e51d81be650dd5eec92f4fe8ae1"
	pmSmokeIndexTag     = "fixture"
	pmSmokeNotes        = "fixture-lib notes\n"
	pmSmokeLockPath     = "var/lib/pm/index.json"
	pmSmokeReceiptPath  = "var/lib/pm/sbom-sources.json"
)

// pmSmokePacket is the pm packages index entry. The pm module publishes only its sbom
// packages, so the index this test serves is spelled here rather than imported.
type pmSmokePacket struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Arch    []string `json:"arch"`
	Default bool     `json:"default"`
	Digest  string   `json:"digest"`
}

func pmSmokeBinary() string {
	ginkgo.GinkgoHelper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		ginkgo.Skip("an actual pm install runs only on linux/amd64")
	}
	path := os.Getenv("DK_PM_BINARY")
	if path == "" {
		ginkgo.Skip("requires pinned DK_PM_BINARY")
	}
	body, err := os.ReadFile(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(digest(body)).To(gomega.Equal(pmSmokeBinarySHA256))

	return path
}

func pmSmokeDir() string {
	ginkgo.GinkgoHelper()
	directory, err := filepath.EvalSymlinks(ginkgo.GinkgoT().TempDir())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return directory
}

func pmSmokeRegistry(ctx context.Context) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(docker_registry.Init(ctx, true, false, nil, nil)).To(gomega.Succeed())
	server := httptest.NewServer(registry.New())
	ginkgo.DeferCleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://") + "/packages"
}

// pmSmokePackageImage is an ordinary package image: one layer of package-relative paths,
// owned by the user running the test so that an unprivileged pm can unpack it into an
// isolated root, and configured for the platform the packet declares.
func pmSmokePackageImage(files map[string][]byte) v1.Image {
	ginkgo.GinkgoHelper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, path := range slices.Sorted(maps.Keys(files)) {
		mode := int64(0o644)
		if bytes.HasPrefix(files[path], []byte("\x7fELF")) {
			mode = 0o755
		}
		header := &tar.Header{Name: path, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(files[path])), Uid: os.Getuid(), Gid: os.Getgid()}
		gomega.Expect(writer.WriteHeader(header)).To(gomega.Succeed())
		_, err := writer.Write(files[path])
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	gomega.Expect(writer.Close()).To(gomega.Succeed())
	layer, err := fixtureLayer(buffer.Bytes())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	config, err := image.ConfigFile()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	config.OS, config.Architecture = "linux", "amd64"
	image, err = mutate.ConfigFile(image, config)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return image
}

func pushPMSmokePacket(ctx context.Context, repo, packet, version string, files map[string][]byte) pmSmokePacket {
	ginkgo.GinkgoHelper()
	image := pmSmokePackageImage(files)
	tag, err := name.NewTag(repo+":"+packet, name.Insecure)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(tag, image, remote.WithContext(ctx))).To(gomega.Succeed())
	pinned, err := image.Digest()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return pmSmokePacket{Name: packet, Version: version, Arch: []string{"linux/amd64"}, Default: true, Digest: pinned.String()}
}

func pushPMSmokeIndex(ctx context.Context, repo string, packets []pmSmokePacket) {
	ginkgo.GinkgoHelper()
	body, err := json.Marshal(packets)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image := pmSmokePackageImage(map[string][]byte{"index.json": body})
	tag, err := name.NewTag(repo+"/index:"+pmSmokeIndexTag, name.Insecure)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(remote.Write(tag, image, remote.WithContext(ctx))).To(gomega.Succeed())
}

// runPMSmokeInstall runs the actual pm with explicit absolute paths for everything it
// writes: --rootDir prefixes neither the lock file nor the source receipt.
func runPMSmokeInstall(ctx context.Context, binary, repo, root, packet string) {
	ginkgo.GinkgoHelper()
	limited, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(limited, binary, "install",
		"--registry", repo,
		"--insecure",
		"--packagesVersion", pmSmokeIndexTag,
		"--docker-config-path", pmSmokeDir(),
		"--user", "", "--password", "",
		"--rootDir", root,
		"--lock-file-path", filepath.Join(root, pmSmokeLockPath),
		"--sbom-sources-file", filepath.Join(root, pmSmokeReceiptPath),
		packet)
	// The empty --user/--password above are the whole authentication story: no registry
	// credentials reach this install from the environment.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + pmSmokeDir()}
	output, err := cmd.CombinedOutput()
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "pm install %s: %s", packet, output)
}

// pmSmokeStage indexes a real directory the way a stage image is indexed: its contents
// are handed to the production indexer as one layer, and the same image is what the gate
// verifies.
func pmSmokeStage(ctx context.Context, stage, root string) (SourceSnapshot, v1.Image) {
	ginkgo.GinkgoHelper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	gomega.Expect(filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		if info.IsDir() {
			header.Name += "/"
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		body, err := os.Open(path)
		if err != nil {
			return err
		}
		defer body.Close()
		_, err = io.Copy(writer, body)

		return err
	})).To(gomega.Succeed())
	gomega.Expect(writer.Close()).To(gomega.Succeed())

	layer, err := fixtureLayer(buffer.Bytes())
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	image, err := mutate.AppendLayers(empty.Image, layer)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	index, err := shippedscope.IndexImageFiles(ctx, image)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(index.Incomplete).To(gomega.BeFalse())

	return SourceSnapshot{Stage: stage, Index: index}, image
}

func pmSmokeProperty(bom *cdx.BOM, property string) string {
	ginkgo.GinkgoHelper()
	gomega.Expect(bom.Metadata).NotTo(gomega.BeNil())
	gomega.Expect(bom.Metadata.Properties).NotTo(gomega.BeNil())
	for _, candidate := range *bom.Metadata.Properties {
		if candidate.Name == property {
			return candidate.Value
		}
	}
	ginkgo.Fail("no " + property + " property")

	return ""
}

func pmSmokeOriginals(bom *cdx.BOM) originalsCatalog {
	ginkgo.GinkgoHelper()
	var catalog originalsCatalog
	gomega.Expect(json.Unmarshal([]byte(pmSmokeProperty(bom, originalsProperty)), &catalog)).To(gomega.Succeed())

	return catalog
}

func pmSmokeRecords(bom *cdx.BOM) map[string]Record {
	ginkgo.GinkgoHelper()
	var catalog Catalog
	gomega.Expect(json.Unmarshal([]byte(pmSmokeProperty(bom, catalogProperty)), &catalog)).To(gomega.Succeed())
	records := make(map[string]Record, len(catalog.Records))
	for _, record := range catalog.Records {
		records[record.Path] = record
	}

	return records
}

// pmSmokePackages maps the components that are not per-file entries, which is what the
// owning packets and the producer's own composition appear as.
func pmSmokePackages(bom *cdx.BOM) map[string]string {
	ginkgo.GinkgoHelper()
	gomega.Expect(bom.Components).NotTo(gomega.BeNil())
	packages := map[string]string{}
	for _, component := range *bom.Components {
		if component.Type != cdx.ComponentTypeFile {
			packages[component.Name] = component.Version
		}
	}

	return packages
}

// pmSmokeSourceID names the recorded source whose Packet is this packet.
func pmSmokeSourceID(catalog originalsCatalog, packet pmSmokePacket) string {
	ginkgo.GinkgoHelper()
	for _, id := range slices.Sorted(maps.Keys(catalog.Sources)) {
		var recorded pmSmokePacket
		gomega.Expect(json.Unmarshal(catalog.Sources[id].Packet, &recorded)).To(gomega.Succeed())
		if recorded.Name == packet.Name && recorded.Version == packet.Version && recorded.Digest == packet.Digest {
			return id
		}
	}
	ginkgo.Fail("no recorded source for " + packet.Name)

	return ""
}

var _ = ginkgo.Describe("Actual pm install", func() {
	ginkgo.It("verifies what two actual installs leave, carries it through a shell move and hands one file to an import", func(ctx ginkgo.SpecContext) {
		binary := pmSmokeBinary()
		app, _, policy := pureGoFixture()

		repo := pmSmokeRegistry(ctx)
		lib := pushPMSmokePacket(ctx, repo, "fixture-lib", "0.9.1", map[string][]byte{"usr/share/fixture-lib/notes.txt": []byte(pmSmokeNotes)})
		tool := pushPMSmokePacket(ctx, repo, "fixture-tool", "1.2.3", map[string][]byte{"usr/bin/fixture-tool": app})
		pushPMSmokeIndex(ctx, repo, []pmSmokePacket{tool, lib})

		root := pmSmokeDir()
		gomega.Expect(os.MkdirAll(filepath.Join(root, filepath.Dir(pmSmokeLockPath)), 0o755)).To(gomega.Succeed())
		runPMSmokeInstall(ctx, binary, repo, root, "fixture-lib@0.9.1")
		runPMSmokeInstall(ctx, binary, repo, root, "fixture-tool@1.2.3")

		gomega.Expect(os.ReadFile(filepath.Join(root, "usr/bin/fixture-tool"))).To(gomega.Equal(app))
		gomega.Expect(os.ReadFile(filepath.Join(root, "usr/share/fixture-lib/notes.txt"))).To(gomega.Equal([]byte(pmSmokeNotes)))

		written, err := os.ReadFile(filepath.Join(root, pmSmokeReceiptPath))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		receipt, status, err := sources.Parse(written)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(status).To(gomega.Equal("present"))
		gomega.Expect(receipt.Sources).To(gomega.HaveLen(2))

		// An install of what is already installed opens no package, so it has nothing to
		// record and must not invent a source.
		runPMSmokeInstall(ctx, binary, repo, root, "fixture-lib@0.9.1")
		gomega.Expect(os.ReadFile(filepath.Join(root, pmSmokeReceiptPath))).To(gomega.Equal(written))

		packages, _ := pmSmokeStage(ctx, "packages", root)
		packages.Receipt = receipt

		// The shell stage of an ordinary build: the binary is moved and the receipt, which
		// belongs to the build rather than to the image, is removed.
		gomega.Expect(os.MkdirAll(filepath.Join(root, "opt"), 0o755)).To(gomega.Succeed())
		gomega.Expect(os.Rename(filepath.Join(root, "usr/bin/fixture-tool"), filepath.Join(root, "opt/app"))).To(gomega.Succeed())
		gomega.Expect(os.Remove(filepath.Join(root, pmSmokeReceiptPath))).To(gomega.Succeed())

		from, _ := pmSmokeStage(ctx, "from", pmSmokeDir())
		install, image := pmSmokeStage(ctx, "install", root)
		produced := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, policy, "app", image, []SourceSnapshot{from, packages, install}, produced, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())

		catalog := pmSmokeOriginals(produced)
		toolID, libID := pmSmokeSourceID(catalog, tool), pmSmokeSourceID(catalog, lib)
		gomega.Expect(slices.Sorted(maps.Keys(catalog.Files))).To(gomega.Equal([]string{"/opt/app", "/usr/share/fixture-lib/notes.txt"}))
		gomega.Expect(catalog.Files["/opt/app"]).To(gomega.Equal(originalFileRecord{
			SHA256:   digest(app),
			Size:     int64(len(app)),
			Bindings: []originalBinding{{Source: toolID, Path: "usr/bin/fixture-tool"}},
		}))
		gomega.Expect(catalog.Files["/usr/share/fixture-lib/notes.txt"]).To(gomega.Equal(originalFileRecord{
			SHA256:   digest([]byte(pmSmokeNotes)),
			Size:     int64(len(pmSmokeNotes)),
			Bindings: []originalBinding{{Source: libID, Path: "usr/share/fixture-lib/notes.txt"}},
		}))

		// The lock file pm wrote comes from no package, so it owns nothing and is left out.
		records := pmSmokeRecords(produced)
		gomega.Expect(slices.Sorted(maps.Keys(records))).To(gomega.Equal([]string{"/opt/app", "/usr/share/fixture-lib/notes.txt"}))
		gomega.Expect(records["/opt/app"].SHA256).To(gomega.Equal(digest(app)))
		gomega.Expect(records["/opt/app"].Origin).To(gomega.Equal("pm"))
		gomega.Expect(records["/opt/app"].Profile).To(gomega.Equal("go"))
		gomega.Expect(records["/opt/app"].Owners).To(gomega.Equal([]string{toolID}))
		gomega.Expect(records["/opt/app"].Components).To(gomega.ContainElement(toolID))
		gomega.Expect(records["/usr/share/fixture-lib/notes.txt"].Owners).To(gomega.Equal([]string{libID}))
		gomega.Expect(pmSmokePackages(produced)).To(gomega.Equal(map[string]string{
			"sbom.test/app": "0.0.1",
			"golang":        "1.27.3",
			"fixture-tool":  "1.2.3",
			"fixture-lib":   "0.9.1",
		}))

		// A consumer gets the producer's SBOM as published JSON and one imported file.
		data, err := cyclonedxutil.ToJSON(produced)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		published, err := cyclonedxutil.BuildCycloneDX16BOMFromJSON(data)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		consumerRoot := pmSmokeDir()
		scope := ImportScope{FromPath: "/opt/app", ToPath: "/app"}
		runImport(ctx, root, consumerRoot, scope)
		consumerFrom, _ := pmSmokeStage(ctx, "from", pmSmokeDir())
		dependencies, consumerImage := pmSmokeStage(ctx, "dependencies", consumerRoot)
		dependencies.Imports = []SourceImport{{Index: install.Index, BOM: published, Scope: scope}}
		consumed := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, policy, "app", consumerImage, []SourceSnapshot{consumerFrom, dependencies}, consumed, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())

		imported := pmSmokeOriginals(consumed)
		gomega.Expect(slices.Sorted(maps.Keys(imported.Files))).To(gomega.Equal([]string{"/app"}))
		gomega.Expect(imported.Files["/app"]).To(gomega.Equal(originalFileRecord{
			SHA256:   digest(app),
			Size:     int64(len(app)),
			Bindings: []originalBinding{{Source: pmSmokeSourceID(imported, tool), Path: "usr/bin/fixture-tool"}},
		}))
		gomega.Expect(pmSmokeRecords(consumed)["/app"].Owners).To(gomega.Equal([]string{pmSmokeSourceID(imported, tool)}))
		gomega.Expect(pmSmokePackages(consumed)).To(gomega.Equal(map[string]string{
			"sbom.test/app": "0.0.1",
			"golang":        "1.27.3",
			"fixture-tool":  "1.2.3",
		}))

		// The same installed files, with nothing saying which packages they came from.
		unreferenced := packages
		unreferenced.Receipt = nil
		err = ApplySourceSnapshots(ctx, policy, "app", image, []SourceSnapshot{from, unreferenced, install}, cdx.NewBOM(), ApplySourceSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: pm index has no original source receipt at packages")))

		dependencies.Imports = []SourceImport{{Index: install.Index, Scope: scope}}
		err = ApplySourceSnapshots(ctx, policy, "app", consumerImage, []SourceSnapshot{consumerFrom, dependencies}, cdx.NewBOM(), ApplySourceSnapshotsOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("no-data: pm index has no original source receipt at import source")))
	})
})
