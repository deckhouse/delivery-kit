package nativegate

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("image source transport", func() {
	ginkgo.It("does not manufacture a confirmed empty receipt when package state is absent", func() {
		binary := filepath.Join(ginkgo.GinkgoT().TempDir(), "pm")
		body := []byte("#!/bin/sh\nprintf '%s\\n' 'no-data: missing receipt' >&2\nexit 2\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		_, err := ImagePackageSources(context.Background(), fixtureImage(nil), ginkgo.GinkgoT().TempDir(), ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(body), "sha256:")})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("missing receipt"), gomega.ContainSubstring("exit status 2"))))
	})
	ginkgo.It("passes the image package state to pm without executing image files", func() {
		directory := ginkgo.GinkgoT().TempDir()
		binary := filepath.Join(ginkgo.GinkgoT().TempDir(), "pm")
		body := []byte("#!/bin/sh\ncat \"$3/var/lib/pm/sbom-sources.json\"\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		receipt, err := ImagePackageSources(context.Background(), fixtureImage(map[string][]byte{"/var/lib/pm/sbom-sources.json": []byte(`{"version":1,"sources":[]}`), "/outside": []byte("not extracted")}), directory, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(body), "sha256:")})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(receipt.Sources).To(gomega.BeEmpty())
		_, err = os.Stat(filepath.Join(directory, "outside"))
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())
	})
	ginkgo.It("round trips source file ownership through standard CycloneDX fields", func() {
		bom := cdx.NewBOM()
		opts := VerifyOptions{Subject: "app", Platform: "linux/amd64", UserRoots: []string{"/src"}, Originals: []Original{{Path: "/src/a.c", SHA256: fixtureDigest([]byte("source")), Component: fixtureComponent("git"), Kind: "git"}}}
		gomega.Expect(Verify(context.Background(), fixtureImage(map[string][]byte{"/src/a.c": []byte("source")}), bom, opts)).To(gomega.Succeed())
		originals, err := ImageOriginals(context.Background(), bom, "linux/amd64")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(originals).To(gomega.HaveLen(1))
		gomega.Expect(originals[0].Component.BOMRef).To(gomega.Equal("git"))
		gomega.Expect(originals[0].SHA256).To(gomega.Equal(fixtureDigest([]byte("source"))))
	})
})
