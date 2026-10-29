package build

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/logging"
)

var _ = ginkgo.Describe("verified primary Webpack stage inputs", func() {
	ginkgo.It("delivers expected hashes only when the checked stage asks for them", func(specCtx ginkgo.SpecContext) {
		ctx := logging.WithLogger(specCtx)
		plain := newProducerFixture(ctx, producerFixtureOptions{})
		base, err := plain.phase.producerContext(ctx, plain.img, plain.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ginkgo.DeferCleanup(func() { gomega.Expect(os.RemoveAll(base.directory)).To(gomega.Succeed()) })
		_, err = os.Stat(filepath.Join(base.directory, "webpack-originals.json"))
		gomega.Expect(os.IsNotExist(err)).To(gomega.BeTrue())

		declaration := strings.Replace(producerDeclaration(), `"subject":0`, `"subject":0,"webpackSources":true`, 1)
		flagged := newProducerFixture(ctx, producerFixtureOptions{declaration: declaration})
		input, err := flagged.phase.producerContext(ctx, flagged.img, flagged.stg)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		ginkgo.DeferCleanup(func() { gomega.Expect(os.RemoveAll(input.directory)).To(gomega.Succeed()) })
		body, err := os.ReadFile(filepath.Join(input.directory, "webpack-originals.json"))
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(string(body)).To(gomega.ContainSubstring(`"path":"/src/main.c"`))
		gomega.Expect(string(body)).NotTo(gomega.ContainSubstring("unused.c"))
		gomega.Expect(producerWrittenContext(input).Subject.Name).To(gomega.Equal(producerSourceName))
		gomega.Expect(input.checksum).NotTo(gomega.Equal(base.checksum))
	})
	ginkgo.DescribeTable("refuses an invalid opt-in", func(value string) {
		declaration := strings.Replace(producerDeclaration(), `"subject":0`, `"subject":0,"webpackSources":`+value, 1)
		_, err := parseSBOMBuildContextDeclaration([]byte(declaration))
		gomega.Expect(err).To(gomega.HaveOccurred())
	}, ginkgo.Entry("null", "null"), ginkgo.Entry("string", `"true"`), ginkgo.Entry("object", "{}"))
})
