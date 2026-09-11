package container_backend

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/werf/werf/v2/pkg/sbom/scanner"
)

var _ = Describe("mapSbomScanOptionsToDockerRunCommand", func() {
	newScanOpts := func(sourceType scanner.SourceType, sourcePath string) scanner.ScanOptions {
		cmd := scanner.NewSyftScanCommand()
		cmd.SourceType = sourceType
		cmd.SourcePath = sourcePath
		return scanner.ScanOptions{
			Image:      "anchore/syft:v1.45.1",
			PullPolicy: scanner.PullIfMissing,
			Commands:   []scanner.ScanCommand{cmd},
		}
	}

	It("scans a directory source over a bind mount without docker.sock", func() {
		scanOpts := newScanOpts(scanner.SourceTypeDir, "/host/scan/dir")
		billNames := scanner.BillNamesFromCommands(scanOpts.Commands)

		args := mapSbomScanOptionsToDockerRunCommand("/wt", "sbom", billNames, scanOpts)
		joined := strings.Join(args, " ")

		Expect(joined).ToNot(ContainSubstring("/var/run/docker.sock"))
		Expect(args).To(ContainElement("/host/scan/dir:/scan:ro"))
		Expect(joined).To(ContainSubstring("scan dir:/scan"))
	})

	It("keeps the docker.sock mount and docker source for full-image scans", func() {
		scanOpts := newScanOpts(scanner.SourceTypeDocker, "example.com/app:latest")
		billNames := scanner.BillNamesFromCommands(scanOpts.Commands)

		args := mapSbomScanOptionsToDockerRunCommand("/wt", "sbom", billNames, scanOpts)
		joined := strings.Join(args, " ")

		Expect(args).To(ContainElement("/var/run/docker.sock:/var/run/docker.sock"))
		Expect(joined).To(ContainSubstring("scan docker:example.com/app:latest"))
	})
})
