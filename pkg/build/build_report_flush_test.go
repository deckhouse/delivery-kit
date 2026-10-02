package build

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/opstats"
)

var _ = Describe("createBuildReport operations flush", func() {
	It("does not lose pending observations when the report write fails", func() {
		collector := opstats.NewCollector()
		ctx := opstats.NewContext(context.Background(), collector)

		opstats.Observe(ctx, opstats.Operation("docker: image build"))()
		opstats.CountEvent(ctx, opstats.EventStageBuilt)

		failPhase := &BuildPhase{
			ImagesReport: NewImagesReport(),
			BuildPhaseOptions: BuildPhaseOptions{BuildOptions: BuildOptions{
				ReportPath:   filepath.Join(GinkgoT().TempDir(), "missing-dir", "report.json"),
				ReportFormat: ReportJSON,
			}},
		}
		Expect(createBuildReport(ctx, failPhase, nil)).To(HaveOccurred())

		opstats.Observe(ctx, opstats.Operation("docker: image build"))()
		opstats.CountEvent(ctx, opstats.EventStageBuilt)

		reportPath := filepath.Join(GinkgoT().TempDir(), "report.json")
		okPhase := &BuildPhase{
			ImagesReport: NewImagesReport(),
			BuildPhaseOptions: BuildPhaseOptions{BuildOptions: BuildOptions{
				ReportPath:   reportPath,
				ReportFormat: ReportJSON,
			}},
		}
		Expect(createBuildReport(ctx, okPhase, nil)).To(Succeed())

		data, err := os.ReadFile(reportPath)
		Expect(err).NotTo(HaveOccurred())

		var decoded struct {
			Operations map[string]ReportOperationRecord
			StageCache map[string]int
		}
		Expect(json.Unmarshal(data, &decoded)).To(Succeed())
		Expect(decoded.Operations[string(opstats.Operation("docker: image build"))].Count).To(Equal(2))
		Expect(decoded.StageCache[string(opstats.EventStageBuilt)]).To(Equal(2))

		Expect(collector.PendingSummary(ctx)).To(BeEmpty())
		Expect(collector.PendingEventSummary(ctx)).To(BeEmpty())
	})
})
