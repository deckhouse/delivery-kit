package nativegate

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("package install boundaries", func() {
	ginkgo.It("refuses a parent alias that would hide package state from capture", func() {
		view := &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{"/var": "/state"}, Directories: map[string]struct{}{"/": {}}}}
		_, err := CollectPackageSources(context.Background(), []PackageSnapshot{{Stage: "from", View: view}}, ginkgo.GinkgoT().TempDir(), ReadPackageSourcesOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("/var"), gomega.ContainSubstring("symlink"))))
	})
	ginkgo.It("proves an empty package set from an entire scratch chain without invoking pm", func() {
		view := &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Symlinks: map[string]string{}, Directories: map[string]struct{}{"/": {}}}}
		receipt, err := CollectPackageSources(context.Background(), []PackageSnapshot{{Stage: "from", View: view}, {Stage: "setup", View: view}}, ginkgo.GinkgoT().TempDir(), ReadPackageSourcesOptions{Binary: "/must/not/run", SHA256: strings.Repeat("0", 64)})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(receipt.Sources).To(gomega.BeEmpty())
	})
	ginkgo.It("retains command sources from installation after the state directory is deleted", func() {
		root := ginkgo.GinkgoT().TempDir()
		binary := filepath.Join(root, "pm")
		body := []byte("#!/bin/sh\ncat \"$3/var/lib/pm/sbom-sources.json\"\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		data := []byte(`{"version":1,"sources":[{"registry":"registry.example.invalid/packages","platform":"linux/amd64","packet":{"name":"data","version":"1","digest":"sha256:` + strings.Repeat("1", 64) + `","arch":["linux/amd64"]}}]}`)
		installed := &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{"/var/lib/pm/sbom-sources.json": {Digest: fixtureDigest(data), Size: int64(len(data))}}, Directories: map[string]struct{}{"/var/lib/pm": {}}}, Bodies: map[string][]byte{"/var/lib/pm/sbom-sources.json": data}}
		deleted := &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Directories: map[string]struct{}{"/": {}}}}
		receipt, err := CollectPackageSources(context.Background(), []PackageSnapshot{{Stage: "from", View: deleted}, {Stage: "packages", View: installed, RequiresSources: true}, {Stage: "setup", View: deleted}}, root, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(body), "sha256:")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(receipt.Sources).To(gomega.HaveLen(1))
	})
	ginkgo.It("refuses a declared installation without source state", func() {
		view := &shippedscope.ImageSnapshot{Index: &shippedscope.FileIndex{Files: map[string]shippedscope.File{}, Directories: map[string]struct{}{"/": {}}}}
		_, err := CollectPackageSources(context.Background(), []PackageSnapshot{{Stage: "packages", View: view, RequiresSources: true}}, ginkgo.GinkgoT().TempDir(), ReadPackageSourcesOptions{})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("packages"), gomega.ContainSubstring("/var/lib/pm"), gomega.ContainSubstring("no-data"))))
	})
})
