package container_backend

import (
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/image"
)

var _ = ginkgo.Describe("SBOM stage record in legacy Docker commit", func() {
	ginkgo.DescribeTable("preserves JSON quotes through Dockerfile expansion", func(ctx ginkgo.SpecContext, exact bool) {
		const record = `{"stage":"install","stageDigest":"abc","parentStageID":"def-1"}`
		opts := &LegacyStageImageContainerOptions{Label: map[string]string{image.WerfSBOMStageLabel: record}}
		prepared, err := opts.prepareCommitChanges(ctx, LegacyCommitChangeOptions{ExactValues: exact})
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		for _, changes := range [][]string{prepared, opts.toCommitChanges(LegacyCommitChangeOptions{ExactValues: exact})} {
			found := false
			for _, change := range changes {
				value, ok := strings.CutPrefix(change, "LABEL "+image.WerfSBOMStageLabel+"=")
				if !ok {
					continue
				}
				found = true
				decoded, _, err := shell.NewLex('\\').ProcessWord(value, shell.EnvsFromSlice([]string{}))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(decoded).To(gomega.Equal(record))
			}
			gomega.Expect(found).To(gomega.BeTrue())
		}
	}, ginkgo.Entry("legacy interpretation", false), ginkgo.Entry("exact values", true))
})
