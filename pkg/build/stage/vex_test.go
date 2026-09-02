package stage

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/build/signing"
)

var _ = Describe("VexStage dependencies", func() {
	It("changes when the VEX document changes", func(ctx SpecContext) {
		first, err := GenerateVexStage([]byte(`{"statements":[]}`), &BaseStageOptions{TargetPlatform: ""}, signing.VexSigningOptions{}).GetDependencies(ctx, nil, nil, nil, nil, nil)
		Expect(err).To(Succeed())
		second, err := GenerateVexStage([]byte(`{"statements":[{"status":"not_affected"}]}`), &BaseStageOptions{TargetPlatform: ""}, signing.VexSigningOptions{}).GetDependencies(ctx, nil, nil, nil, nil, nil)
		Expect(err).To(Succeed())

		Expect(first).NotTo(Equal(second))
		content, err := GenerateVexStage([]byte(`{"statements":[]}`), &BaseStageOptions{TargetPlatform: ""}, signing.VexSigningOptions{}).GetContentDependencies(ctx, nil, nil)
		Expect(err).To(Succeed())
		Expect(content).To(Equal(first))
	})
})
