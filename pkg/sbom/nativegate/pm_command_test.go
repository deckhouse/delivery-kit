package nativegate

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("pm source command", func() {
	var root, binary, checksum string
	ginkgo.BeforeEach(func() {
		root = ginkgo.GinkgoT().TempDir()
		binary = filepath.Join(root, "pm")
		body := []byte("#!/bin/sh\n[ \"$1\" = sbom-sources ] && [ \"$2\" = --root ] && [ -d \"$3\" ] || exit 9\nprintf '%s\\n' '{\"version\":1,\"sources\":[]}'\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		checksum = strings.TrimPrefix(fixtureDigest(body), "sha256:")
	})
	ginkgo.It("invokes the pinned host binary with the stage root", func() {
		receipt, err := ReadPackageSources(context.Background(), root, ReadPackageSourcesOptions{Binary: binary, SHA256: checksum})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(receipt.Sources).To(gomega.BeEmpty())
	})
	ginkgo.It("refuses a different executable before starting it", func() {
		_, err := ReadPackageSources(context.Background(), root, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.Repeat("0", 64)})
		gomega.Expect(err).To(gomega.MatchError(gomega.ContainSubstring("SHA256")))
	})
	ginkgo.DescribeTable("never treats failure as an empty package set", func(code string) {
		body := []byte("#!/bin/sh\nprintf '%s\\n' 'no-data: source missing' >&2\nexit " + code + "\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		_, err := ReadPackageSources(context.Background(), root, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(body), "sha256:")})
		gomega.Expect(err).To(gomega.MatchError(gomega.And(gomega.ContainSubstring("source missing"), gomega.ContainSubstring("exit status "+code))))
	}, ginkgo.Entry("invalid", "1"), ginkgo.Entry("no-data", "2"))
	ginkgo.DescribeTable("rejects malformed successful output", func(payload string) {
		body := []byte("#!/bin/sh\nprintf '%s\\n' '" + payload + "'\n")
		gomega.Expect(os.WriteFile(binary, body, 0o700)).To(gomega.Succeed())
		_, err := ReadPackageSources(context.Background(), root, ReadPackageSourcesOptions{Binary: binary, SHA256: strings.TrimPrefix(fixtureDigest(body), "sha256:")})
		gomega.Expect(err).To(gomega.HaveOccurred())
	}, ginkgo.Entry("truncated JSON", `{"version":1`), ginkgo.Entry("missing sources", `{"version":1}`), ginkgo.Entry("unsupported version", `{"version":2,"sources":[]}`), ginkgo.Entry("trailing document", `{"version":1,"sources":[]} {}`))
})
