package checker

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/werf/werf/v2/pkg/sbom/ispras"
)

var _ = Describe("checker", func() {
	Describe("parseResult", func() {
		DescribeTable("splits checker output into errors and warnings",
			func(out string, want fileResult) {
				Expect(parseResult(out)).To(Equal(want))
			},
			Entry("no errors no warnings",
				"файл корректный\n",
				fileResult{}),
			Entry("empty output",
				"",
				fileResult{}),
			Entry("errors only",
				"ERROR: missing bomFormat\nERROR: missing specVersion\n",
				fileResult{errs: []string{"ERROR: missing bomFormat", "ERROR: missing specVersion"}}),
			Entry("warnings only",
				"WARNING: vcs url not found for pkg1\nWARNING: vcs url not found for pkg2\n",
				fileResult{warnings: []string{"WARNING: vcs url not found for pkg1", "WARNING: vcs url not found for pkg2"}}),
			Entry("errors and warnings mixed with non-prefixed lines",
				"starting check\nERROR: bad field\nWARNING: vcs issue\ndone\n",
				fileResult{errs: []string{"ERROR: bad field"}, warnings: []string{"WARNING: vcs issue"}}),
		)
	})

	Describe("fileResult.report", func() {
		DescribeTable("fails only on errors unless failOnWarnings is set",
			func(res fileResult, failOnWarnings bool, matcher types.GomegaMatcher) {
				err := res.report(context.Background(), "sbom.json", 1, 1, failOnWarnings)
				Expect(err).To(matcher)
			},
			Entry("clean result passes",
				fileResult{}, false,
				Succeed()),
			Entry("clean result passes with failOnWarnings",
				fileResult{}, true,
				Succeed()),
			Entry("errors fail",
				fileResult{errs: []string{"ERROR: missing bomFormat", "ERROR: missing specVersion"}}, false,
				MatchError(And(
					ContainSubstring("validation failed for sbom.json"),
					ContainSubstring("ERROR: missing bomFormat"),
					ContainSubstring("ERROR: missing specVersion"),
				))),
			Entry("warnings alone pass by default",
				fileResult{warnings: []string{"WARNING: vcs url not found"}}, false,
				Succeed()),
			Entry("warnings alone fail with failOnWarnings",
				fileResult{warnings: []string{"WARNING: vcs url not found"}}, true,
				MatchError(And(
					ContainSubstring("validation failed for sbom.json"),
					ContainSubstring("WARNING: vcs url not found"),
				))),
			Entry("errors with warnings fail and report both",
				fileResult{errs: []string{"ERROR: bad field"}, warnings: []string{"WARNING: vcs issue"}}, false,
				MatchError(And(
					ContainSubstring("ERROR: bad field"),
					ContainSubstring("WARNING: vcs issue"),
				))),
		)
	})

	Describe("buildDockerArgs", func() {
		DescribeTable("builds correct docker arguments",
			func(path string, format ispras.Format, checkVCS bool, want []string) {
				got, err := buildDockerArgs(path, format, checkVCS)
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(want))
			},
			Entry("oss without check-vcs",
				"/tmp/sbom.json", ispras.FormatOSS, false,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "/sbom/input.json",
				}),
			Entry("oss with check-vcs",
				"/tmp/sbom.json", ispras.FormatOSS, true,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--check-vcs", "/sbom/input.json",
				}),
			Entry("container format",
				"/tmp/sbom.json", ispras.FormatContainer, false,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "container", "--errors", "0", "/sbom/input.json",
				}),
			Entry("container with check-vcs",
				"/tmp/sbom.json", ispras.FormatContainer, true,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "container", "--errors", "0", "--check-vcs", "/sbom/input.json",
				}),
		)
	})

	Describe("extractPrefixedLines", func() {
		DescribeTable("extracts lines with given prefix",
			func(text, prefix string, want []string) {
				Expect(extractPrefixedLines(text, prefix)).To(Equal(want))
			},
			Entry("no matching lines",
				"some output\nanother line\n", "ERROR:",
				[]string(nil)),
			Entry("single error line",
				"ERROR: bad field\n", "ERROR:",
				[]string{"ERROR: bad field"}),
			Entry("multiple error lines",
				"ERROR: first\nok\nERROR: second\n", "ERROR:",
				[]string{"ERROR: first", "ERROR: second"}),
			Entry("warning lines",
				"WARNING: vcs not found\nWARNING: another\n", "WARNING:",
				[]string{"WARNING: vcs not found", "WARNING: another"}),
			Entry("trims whitespace before matching",
				"  ERROR: indented\n\tERROR: tabbed\n", "ERROR:",
				[]string{"ERROR: indented", "ERROR: tabbed"}),
			Entry("empty input",
				"", "ERROR:",
				[]string(nil)),
		)
	})
})
