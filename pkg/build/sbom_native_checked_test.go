package build

import (
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/build/stage"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/sbom/nativegate"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("checked producer stage evidence", func() {
	ginkgo.DescribeTable("refuses pm aliases before ignoring the stock baseline", func(link string) {
		statePath := "/var/lib/pm/index.json"
		filename := path.Join("/outside", strings.TrimPrefix(statePath, link+"/"))
		base := nativeStageSnapshot(map[string]string{filename: "stock"})
		changed := nativeStageSnapshot(map[string]string{filename: "new-install"})
		base.Index.Symlinks[link], changed.Index.Symlinks[link] = "/outside", "/outside"
		_, err := nativeCheckedPackageSnapshots([]nativegate.PackageSnapshot{{Stage: "from", View: base}, {Stage: "install", View: changed}})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(link), gomega.ContainSubstring("symlink"))))
	}, ginkgo.Entry("pm root", "/var/lib/pm"), ginkgo.Entry("lib parent", "/var/lib"), ginkgo.Entry("var parent", "/var"))
	ginkgo.It("declares the configured WorkingDir before the imageSpec stage runs", func(ctx ginkgo.SpecContext) {
		img := newSBOMStageOrderImage(ctx)
		img.StapelImageConfig.ImageBaseConfig().ImageSpec = &config.ImageSpec{WorkingDir: "/out"}
		roots, err := nativeUserRoots(ctx, img, &v1.ConfigFile{})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(roots).To(gomega.ContainElement("/out"))
	})
	ginkgo.It("does not treat stock or imported bytes as produced by its own stages", func(ctx ginkgo.SpecContext) {
		base := nativeStageSnapshot(map[string]string{"/out/stock": "stock"})
		imported := nativeStageSnapshot(map[string]string{"/out/stock": "stock", "/out/imported": "imported"})
		installed := nativeStageSnapshot(map[string]string{"/out/stock": "stock", "/out/imported": "imported", "/out/generated": "first"})
		replaced := nativeStageSnapshot(map[string]string{"/out/stock": "stock", "/out/imported": "imported", "/out/generated": "replacement"})
		installed.Index.Symlinks["/out/own-link"] = "generated"
		replaced.Index.Symlinks["/out/own-link"] = "imported-replacement"
		provenance := sbomStageProvenance{Snapshots: []sbomStageSnapshot{{Stage: stage.From, LayerCount: 1}, {Stage: stage.DependenciesBeforeInstall, LayerCount: 2}, {Stage: stage.Install, LayerCount: 3}}}
		views := map[int]*shippedscope.ImageSnapshot{1: base, 2: imported, 3: installed, 4: replaced}
		produced, links, err := nativeProducedEntries(ctx, provenance, views)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced).To(gomega.Equal(map[string]string{"/out/generated": installed.Index.Files["/out/generated"].Digest}))
		gomega.Expect(links).To(gomega.Equal(map[string]string{"/out/own-link": "generated"}))
		provenance.Snapshots = append(provenance.Snapshots, sbomStageSnapshot{Stage: stage.DependenciesAfterInstall, LayerCount: 4})
		produced, links, err = nativeProducedEntries(ctx, provenance, views)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(produced).To(gomega.BeEmpty())
		gomega.Expect(links).To(gomega.BeEmpty())
	})
	ginkgo.It("ignores only the unchanged stock pm baseline and still requires new installations", func(ctx ginkgo.SpecContext) {
		base := nativeStageSnapshot(map[string]string{"/var/lib/pm/index.json": "stock"})
		unchanged := nativeStageSnapshot(map[string]string{"/var/lib/pm/index.json": "stock", "/out/file": "generated"})
		snapshots := []nativegate.PackageSnapshot{{Stage: "from", View: base}, {Stage: "install", View: unchanged}}
		filtered, err := nativeCheckedPackageSnapshots(snapshots)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		pm := nativeNoDataPMCommand()
		_, err = nativegate.CollectPackageSources(ctx, filtered, ginkgo.GinkgoT().TempDir(), pm)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		snapshots[1].RequiresSources = true
		filtered, err = nativeCheckedPackageSnapshots(snapshots)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(filtered[1].View.Index.Files).To(gomega.HaveKey("/var/lib/pm/index.json"))
		_, err = nativegate.CollectPackageSources(ctx, filtered, ginkgo.GinkgoT().TempDir(), pm)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("install"), gomega.ContainSubstring("exit status 2"), gomega.ContainSubstring("no-data"))))
	})
	ginkgo.It("retains shell changes to stock pm state instead of hiding no-data", func() {
		base := nativeStageSnapshot(map[string]string{"/var/lib/pm/index.json": "stock"})
		changed := nativeStageSnapshot(map[string]string{"/var/lib/pm/index.json": "new-install"})
		filtered, err := nativeCheckedPackageSnapshots([]nativegate.PackageSnapshot{{Stage: "from", View: base}, {Stage: "install", View: changed}, {Stage: "setup", View: base}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(filtered[1].View).To(gomega.BeIdenticalTo(changed))
		gomega.Expect(filtered[2].View.Index.Files).NotTo(gomega.HaveKey("/var/lib/pm/index.json"))
	})
})
