package nativegate

import (
	"context"
	"debug/elf"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

var _ = ginkgo.Describe("Default composition checks", func() {
	ginkgo.It("accepts producer tool identities without requiring compiler bytes in the final image", func(ctx ginkgo.SpecContext) {
		img := fixtureImage(map[string]string{"/app": string(minimalRuntimeELF(elf.ET_EXEC))})
		before, err := shippedscope.IndexImageFiles(ctx, empty.Image)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		after, err := shippedscope.IndexImageFiles(ctx, img)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		snapshots := []SourceSnapshot{{Stage: "from", Index: before}, {Stage: "install", Index: after}}
		bom := cdx.NewBOM()
		gomega.Expect(ApplySourceSnapshots(ctx, NewDefaultPolicy(context.Background(), "app"), "app", img, snapshots, bom, ApplySourceSnapshotsOptions{})).To(gomega.Succeed())
		gomega.Expect(bom.Components).NotTo(gomega.BeNil())
		gomega.Expect(NewDefaultPolicy(context.Background(), "app").Profiles).To(gomega.Equal([]string{"c-static", "c-dynamic", "go", "go-cgo-dynamic", "go-macho", "go-pe"}))
	})

	ginkgo.DescribeTable("still rejects incomplete tool identities", func(tool Tool) {
		gomega.Expect(NewDefaultPolicy(context.Background(), "app").checkTool(tool)).To(gomega.MatchError(gomega.ContainSubstring("incomplete tool identity")))
	},
		ginkgo.Entry("missing name", Tool{Version: "1", SHA256: "sha256:" + strings.Repeat("1", 64)}),
		ginkgo.Entry("missing version", Tool{Name: "cc", SHA256: "sha256:" + strings.Repeat("1", 64)}),
		ginkgo.Entry("missing digest", Tool{Name: "cc", Version: "1"}),
		ginkgo.Entry("invalid digest", Tool{Name: "cc", Version: "1", SHA256: "sha256:not-a-hash"}),
	)

	ginkgo.It("does not reinterpret an explicit POC whitelist as producer trust", func() {
		policy := fixturePolicy("app")
		tool := Tool{Name: "other", Version: "2", SHA256: "sha256:" + strings.Repeat("3", 64)}
		gomega.Expect(policy.checkTool(tool)).To(gomega.MatchError(gomega.ContainSubstring("unregistered tool")))
		gomega.Expect(NewDefaultPolicy(context.Background(), "app").checkTool(tool)).To(gomega.Succeed())
	})
})
