package checker

import (
	"context"
	"errors"

	"github.com/docker/cli/cli"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/werf/werf/v2/pkg/sbom/ispras"
)

var _ = Describe("checker", func() {
	Describe("parseResult", func() {
		DescribeTable("parses output correctly",
			func(out string, runErr error, fileName string, index, total int, matcher types.GomegaMatcher) {
				err := parseResult(context.Background(), out, runErr, fileName, index, total)
				Expect(err).To(matcher)
			},
			Entry("no errors no warnings",
				"файл корректный\n", nil, "valid.json", 1, 1,
				Succeed()),
			Entry("empty output",
				"", nil, "empty.json", 1, 1,
				MatchError(And(
					ContainSubstring("validation failed for empty.json"),
					ContainSubstring("checker produced no output"),
				))),
			Entry("whitespace-only output",
				"\n  \n", nil, "empty.json", 1, 1,
				MatchError(ContainSubstring("checker produced no output"))),
			Entry("errors only",
				"ERROR: missing bomFormat\nERROR: missing specVersion\n", nil, "bad.json", 1, 3,
				MatchError(ContainSubstring("validation failed for bad.json"))),
			Entry("warnings only",
				"WARNING: vcs url not found for pkg1\nWARNING: vcs url not found for pkg2\n", nil, "warn.json", 2, 3,
				MatchError(ContainSubstring("validation failed for warn.json"))),
			Entry("errors and warnings",
				"ERROR: bad field\nWARNING: vcs issue\n", nil, "mixed.json", 1, 1,
				MatchError(ContainSubstring("validation failed for mixed.json"))),
			Entry("non-prefixed output only",
				"some random output\nanother line\n", nil, "random.json", 1, 2,
				Succeed()),
			Entry("errors mixed with non-prefixed lines",
				"starting check\nERROR: bad field\ndone\n", nil, "report.json", 3, 5,
				MatchError(ContainSubstring("validation failed for report.json"))),
			Entry("error details included in message",
				"ERROR: missing bomFormat\nERROR: missing specVersion\n", nil, "bad.json", 1, 1,
				MatchError(And(
					ContainSubstring("ERROR: missing bomFormat"),
					ContainSubstring("ERROR: missing specVersion"),
				))),
			Entry("warning details included in message",
				"WARNING: vcs url not found\n", nil, "warn.json", 1, 1,
				MatchError(ContainSubstring("WARNING: vcs url not found"))),
			Entry("non-prefixed output with non-zero exit",
				"Traceback (most recent call last):\n  File \"/app/sbom-checker.py\", line 46\njson.decoder.JSONDecodeError: Expecting value\n", errors.New("exit status 1"), "broken.json", 1, 1,
				MatchError(And(
					ContainSubstring("validation failed for broken.json"),
					ContainSubstring("checker exited with error: exit status 1"),
					ContainSubstring("json.decoder.JSONDecodeError: Expecting value"),
				))),
			Entry("usage error with non-zero exit",
				"usage: sbom-checker.py [-h] filename\nsbom-checker.py: error: unrecognized arguments: --bogus\n", errors.New("exit status 2"), "valid.json", 1, 1,
				MatchError(And(
					ContainSubstring("checker exited with error: exit status 2"),
					ContainSubstring("unrecognized arguments: --bogus"),
				))),
			Entry("empty output with non-zero exit",
				"", errors.New("exit status 1"), "silent.json", 1, 1,
				MatchError(ContainSubstring("checker exited with error: exit status 1"))),
			Entry("docker status error without message spells out the exit code",
				"Traceback (most recent call last):\nFileNotFoundError: no such file\n", cli.StatusError{StatusCode: 1}, "gone.json", 1, 1,
				MatchError(And(
					ContainSubstring("checker exited with error: exit code 1"),
					ContainSubstring("FileNotFoundError: no such file"),
				))),
			Entry("docker status error with message keeps the message",
				"", cli.StatusError{StatusCode: 125, Status: "no such image"}, "valid.json", 1, 1,
				MatchError(ContainSubstring("checker exited with error: no such image"))),
			Entry("findings with non-zero exit keep findings and omit raw output",
				"starting check\nERROR: bad field\n", errors.New("exit status 1"), "bad.json", 1, 1,
				MatchError(And(
					ContainSubstring("ERROR: bad field"),
					ContainSubstring("checker exited with error: exit status 1"),
					Not(ContainSubstring("starting check")),
				))),
		)
	})

	Describe("buildDockerArgs", func() {
		DescribeTable("builds correct docker arguments",
			func(path string, format ispras.Format, opts RunOptions, want []string) {
				got, err := buildDockerArgs(path, format, opts)
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(want))
			},
			Entry("oss without checks",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "/sbom/input.json",
				}),
			Entry("oss with check-vcs",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{CheckVCS: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--check-vcs", "/sbom/input.json",
				}),
			Entry("oss with check-vcs-leaf-only",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{CheckVCSLeafOnly: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--check-vcs-leaf-only", "/sbom/input.json",
				}),
			Entry("oss with check-source-distribution",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{CheckSourceDistribution: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--check-source-distribution", "/sbom/input.json",
				}),
			Entry("oss with check-vcs and check-source-distribution",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{CheckVCS: true, CheckSourceDistribution: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0",
					"--check-vcs", "--check-source-distribution", "/sbom/input.json",
				}),
			Entry("container format",
				"/tmp/sbom.json", ispras.FormatContainer, RunOptions{},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "container", "--errors", "0", "/sbom/input.json",
				}),
			Entry("container with check-vcs",
				"/tmp/sbom.json", ispras.FormatContainer, RunOptions{CheckVCS: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "container", "--errors", "0", "--check-vcs", "/sbom/input.json",
				}),
		)
	})

	Describe("RunOptions.Validate", func() {
		DescribeTable("accepts combinations the checker honors",
			func(opts RunOptions) {
				Expect(opts.Validate()).To(Succeed())
			},
			Entry("nothing enabled", RunOptions{}),
			Entry("vcs", RunOptions{CheckVCS: true}),
			Entry("leaf-only vcs", RunOptions{CheckVCSLeafOnly: true}),
			Entry("vcs and leaf-only vcs", RunOptions{CheckVCS: true, CheckVCSLeafOnly: true}),
			Entry("source distribution", RunOptions{CheckSourceDistribution: true}),
			Entry("vcs and source distribution", RunOptions{CheckVCS: true, CheckSourceDistribution: true}),
		)

		DescribeTable("rejects leaf-only vcs combined with source distribution",
			func(opts RunOptions) {
				Expect(opts.Validate()).To(MatchError(ContainSubstring("--check-vcs-leaf-only cannot be combined with --check-source-distribution")))
			},
			Entry("leaf-only vcs and source distribution", RunOptions{CheckVCSLeafOnly: true, CheckSourceDistribution: true}),
			Entry("every check", RunOptions{CheckVCS: true, CheckVCSLeafOnly: true, CheckSourceDistribution: true}),
		)
	})

	Describe("enabledChecks", func() {
		DescribeTable("lists the checks the checker really runs",
			func(opts RunOptions, want []string) {
				Expect(enabledChecks(opts)).To(Equal(want))
			},
			Entry("nothing enabled", RunOptions{}, []string(nil)),
			Entry("vcs only", RunOptions{CheckVCS: true}, []string{"VCS"}),
			Entry("leaf-only vcs", RunOptions{CheckVCSLeafOnly: true}, []string{"leaf-only VCS"}),
			Entry("vcs and leaf-only vcs narrows to leaves",
				RunOptions{CheckVCS: true, CheckVCSLeafOnly: true},
				[]string{"leaf-only VCS"}),
			Entry("source distribution alone implies vcs",
				RunOptions{CheckSourceDistribution: true},
				[]string{"VCS", "source distribution"}),
			Entry("vcs and source distribution",
				RunOptions{CheckVCS: true, CheckSourceDistribution: true},
				[]string{"VCS", "source distribution"}),
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
