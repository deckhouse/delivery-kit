package nativegate

import (
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("indexed package identity", func() {
	ginkgo.DescribeTable("rejects package substitution despite a forged pm files ledger", func(ctx ginkgo.SpecContext, filename string, archive bool) {
		original := []byte("original package data")
		if archive {
			original = fixtureArchive("legacy.o", fixtureELF(elf.ET_REL, nil))
		}
		changed := append(append([]byte{}, original...), []byte("tampered")...)
		source, trusted := fixtureRegistryPackageImage(ctx, fixtureImage(map[string][]byte{filename: original}))
		receiptData, err := json.Marshal(&sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ledger, err := json.Marshal(map[string]any{"data": map[string]any{"version": "1", "files": map[string]string{filename: strings.TrimPrefix(fixtureDigest(changed), "sha256:")}, "symlinks": map[string]string{}}})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		files := map[string][]byte{filename: changed, "/var/lib/pm/files.json": ledger, "/var/lib/pm/sbom-sources.json": receiptData}
		index, err := shippedscope.IndexImageFiles(ctx, fixtureImage(files))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		root := ginkgo.GinkgoT().TempDir()
		binary := filepath.Join(root, "pm")
		command := []byte("#!/bin/sh\ncat \"$3/var/lib/pm/sbom-sources.json\"\n")
		gomega.Expect(os.WriteFile(binary, command, 0o700)).To(gomega.Succeed())
		receipt, err := CollectPackageSources(ctx, []PackageSnapshot{{Stage: "install", RequiresSources: true, View: &shippedscope.ImageSnapshot{Index: index, Bodies: files}}}, root, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(command), "sha256:")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		set, err := OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(set.Originals).To(gomega.HaveLen(1))
		gomega.Expect(set.Originals[0].SHA256).To(gomega.Equal(fixtureDigest(original)))
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: set.Originals, TrustedComponents: set.Components}
		files[filename] = original
		gomega.Expect(Verify(ctx, fixtureImage(files), cdx.NewBOM(), opts)).To(gomega.Succeed())
		files[filename] = changed
		err = Verify(ctx, fixtureImage(files), cdx.NewBOM(), opts)
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring(filename), gomega.ContainSubstring("hash-mismatch"))))
	}, ginkgo.Entry("regular package file", "/usr/share/data", false), ginkgo.Entry("pm static archive", "/usr/lib/libdata.a", true))
	ginkgo.It("refuses a registry package outside the pinned instrumented index", func(ctx ginkgo.SpecContext) {
		source, trusted := fixtureRegistryPackage(ctx)
		receipt := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}
		_, err := OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = OpenPackageSet(ctx, receipt, "linux/amd64", TrustedPackages{})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("data"), gomega.ContainSubstring("outside instrumented index"))))
	})
	ginkgo.It("verifies package symlink targets before compilation and publication", func(ctx ginkgo.SpecContext) {
		source, trusted := fixtureRegistryPackage(ctx)
		set, err := OpenPackageSet(ctx, &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(set.Symlinks).To(gomega.Equal(map[string]string{"/usr/share/current": "data"}))
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", Originals: set.Originals, ExpectedSymlinks: set.Symlinks, TrustedComponents: set.Components}
		unchanged := fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "data"})
		gomega.Expect(Verify(ctx, unchanged, cdx.NewBOM(), opts)).To(gomega.Succeed())
		changed := fixtureImageWithLinks(map[string][]byte{"/usr/share/data": []byte("original")}, map[string]string{"/usr/share/current": "missing"})
		gomega.Expect(Verify(ctx, changed, cdx.NewBOM(), opts)).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/usr/share/current"), gomega.ContainSubstring("hash-mismatch"))))
		_, err = MaterializeBuildContext(context.Background(), changed, set, ginkgo.GinkgoT().TempDir(), ContextOptions{Subject: "app", Platform: "linux/amd64", ContainerRoot: "/.werf/context"})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("/usr/share/current")))
	})
	ginkgo.It("uses the pinned package and rejects a forged receipt version", func(ctx ginkgo.SpecContext) {
		source, trusted := fixtureRegistryPackage(ctx)
		receipt := &sources.Receipt{Version: sources.Version, Sources: []sources.Source{source}}
		set, err := OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(set.Originals).To(gomega.HaveLen(1))
		gomega.Expect(set.Components[0].Version).To(gomega.Equal("1"))
		packet, err := readSourcePackage(source)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		packet.Version = "forged"
		receipt.Sources[0].Packet, err = json.Marshal(packet)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		_, err = OpenPackageSet(ctx, receipt, "linux/amd64", trusted)
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("identity contradicts instrumented index")))
	})
})
