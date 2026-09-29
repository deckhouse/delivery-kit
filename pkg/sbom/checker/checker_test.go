package checker

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/docker/cli/cli"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/werf/logboek"
	"github.com/werf/werf/v3/pkg/sbom/ispras"
)

var _ = Describe("checker", func() {
	Describe("parseResult", func() {
		run := func(out string, runErr error, fileName string, index, total int, warningsNonFatal bool) (fileResult, string) {
			var printed bytes.Buffer
			ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&printed, &printed))
			res := parseResult(ctx, out, runErr, fileName, index, total, warningsNonFatal)
			return res, printed.String()
		}

		DescribeTable("decides pass or fail and prints every finding once",
			func(out string, runErr error, fileName string, index, total int, wantFailed bool, printedMatcher types.GomegaMatcher) {
				res, printed := run(out, runErr, fileName, index, total, false)
				Expect(res.failed).To(Equal(wantFailed))
				Expect(printed).To(printedMatcher)
			},
			Entry("no errors no warnings",
				"файл корректный\n", nil, "valid.json", 1, 1, false,
				ContainSubstring("(1/1) valid.json... OK")),
			Entry("empty output",
				"", nil, "empty.json", 1, 1, true,
				And(
					ContainSubstring("(1/1) empty.json... FAILED"),
					ContainSubstring("checker produced no output"),
				)),
			Entry("whitespace-only output",
				"\n  \n", nil, "empty.json", 1, 1, true,
				ContainSubstring("checker produced no output")),
			Entry("errors only",
				"ERROR: missing bomFormat\nERROR: missing specVersion\n", nil, "bad.json", 1, 3, true,
				And(
					ContainSubstring("(1/3) bad.json... FAILED"),
					ContainSubstring("ERROR: missing bomFormat"),
					ContainSubstring("ERROR: missing specVersion"),
					Not(MatchRegexp(`(?s)ERROR: missing bomFormat.*ERROR: missing bomFormat`)),
				)),
			Entry("warnings only",
				"WARNING: vcs url not found for pkg1\nWARNING: vcs url not found for pkg2\n", nil, "warn.json", 2, 3, true,
				And(
					ContainSubstring("(2/3) warn.json... FAILED"),
					ContainSubstring("WARNING: vcs url not found for pkg1"),
					Not(MatchRegexp(`(?s)pkg1.*pkg1`)),
				)),
			Entry("errors and warnings",
				"ERROR: bad field\nWARNING: vcs issue\n", nil, "mixed.json", 1, 1, true,
				And(
					ContainSubstring("ERROR: bad field"),
					ContainSubstring("WARNING: vcs issue"),
				)),
			Entry("non-prefixed output only",
				"some random output\nanother line\n", nil, "random.json", 1, 2, false,
				ContainSubstring("(1/2) random.json... OK")),
			Entry("errors mixed with non-prefixed lines",
				"starting check\nERROR: bad field\ndone\n", nil, "report.json", 3, 5, true,
				ContainSubstring("(3/5) report.json... FAILED")),
			Entry("non-prefixed output with non-zero exit",
				"Traceback (most recent call last):\n  File \"/app/sbom-checker.py\", line 46\njson.decoder.JSONDecodeError: Expecting value\n", errors.New("exit status 1"), "broken.json", 1, 1, true,
				And(
					ContainSubstring("(1/1) broken.json... FAILED"),
					ContainSubstring("checker exited with error: exit status 1"),
					ContainSubstring("json.decoder.JSONDecodeError: Expecting value"),
				)),
			Entry("usage error with non-zero exit",
				"usage: sbom-checker.py [-h] filename\nsbom-checker.py: error: unrecognized arguments: --bogus\n", errors.New("exit status 2"), "valid.json", 1, 1, true,
				And(
					ContainSubstring("checker exited with error: exit status 2"),
					ContainSubstring("unrecognized arguments: --bogus"),
				)),
			Entry("empty output with non-zero exit",
				"", errors.New("exit status 1"), "silent.json", 1, 1, true,
				ContainSubstring("checker exited with error: exit status 1")),
			Entry("docker status error without message spells out the exit code",
				"Traceback (most recent call last):\nFileNotFoundError: no such file\n", cli.StatusError{StatusCode: 1}, "gone.json", 1, 1, true,
				And(
					ContainSubstring("checker exited with error: exit code 1"),
					ContainSubstring("FileNotFoundError: no such file"),
				)),
			Entry("docker status error with message keeps the message",
				"", cli.StatusError{StatusCode: 125, Status: "no such image"}, "valid.json", 1, 1, true,
				ContainSubstring("checker exited with error: no such image")),
			Entry("findings with non-zero exit keep findings once and attach the remaining output",
				"starting check\nERROR: bad field\nTraceback (most recent call last):\nRuntimeError: boom\n", errors.New("exit status 1"), "bad.json", 1, 1, true,
				And(
					ContainSubstring("ERROR: bad field"),
					Not(MatchRegexp(`(?s)ERROR: bad field.*ERROR: bad field`)),
					ContainSubstring("checker exited with error: exit status 1"),
					ContainSubstring("starting check"),
					ContainSubstring("RuntimeError: boom"),
				)),
			Entry("findings with clean exit omit the unprefixed output",
				"starting check\nERROR: bad field\ndone\n", nil, "bad.json", 1, 1, true,
				And(
					ContainSubstring("ERROR: bad field"),
					Not(ContainSubstring("starting check")),
					Not(ContainSubstring("done")),
				)),
		)

		It("prints a checker line longer than the stream width intact", func() {
			var out bytes.Buffer
			ctx := logboek.NewContext(context.Background(), logboek.NewLogger(&out, &out))

			finding := errorPrefix + " " + strings.Repeat("a", 4*logboek.Context(ctx).Streams().ContentWidth())

			Expect(parseResult(ctx, finding+"\n", nil, "bad.json", 1, 1, false).failed).To(BeTrue())
			Expect(out.String()).To(ContainSubstring(finding))
			Expect(logboek.Context(ctx).Streams().IsLineWrappingEnabled()).To(BeTrue())
		})

		DescribeTable("fails on warnings unless warningsNonFatal is set, and counts findings",
			func(out string, runErr error, warningsNonFatal bool, wantErrs, wantWarnings int, wantFailed bool, printedMatcher types.GomegaMatcher) {
				res, printed := run(out, runErr, "sbom.json", 1, 1, warningsNonFatal)
				Expect(res.errCount).To(Equal(wantErrs))
				Expect(res.warningCount).To(Equal(wantWarnings))
				Expect(res.failed).To(Equal(wantFailed))
				Expect(printed).To(printedMatcher)
			},
			Entry("warnings alone fail by default",
				"WARNING: vcs url not found\n", nil, false, 0, 1, true,
				And(
					ContainSubstring("sbom.json... FAILED"),
					ContainSubstring("WARNING: vcs url not found"),
				)),
			Entry("warnings alone pass with warningsNonFatal",
				"WARNING: vcs url not found\nWARNING: another\n", nil, true, 0, 2, false,
				And(
					ContainSubstring("sbom.json... OK (2 warning(s))"),
					ContainSubstring("WARNING: another"),
				)),
			Entry("errors fail even with warningsNonFatal",
				"ERROR: missing bomFormat\n", nil, true, 1, 0, true,
				ContainSubstring("ERROR: missing bomFormat")),
			Entry("errors with warnings fail with warningsNonFatal and report both",
				"ERROR: bad field\nWARNING: vcs issue\n", nil, true, 1, 1, true,
				And(
					ContainSubstring("ERROR: bad field"),
					ContainSubstring("WARNING: vcs issue"),
				)),
			Entry("checker crash fails even with warningsNonFatal",
				"WARNING: vcs issue\nTraceback: boom\n", errors.New("exit status 1"), true, 0, 1, true,
				ContainSubstring("checker exited with error: exit status 1")),
			Entry("empty output fails even with warningsNonFatal",
				"", nil, true, 0, 0, true,
				ContainSubstring("checker produced no output")),
			Entry("clean result passes and counts nothing",
				"файл корректный\n", nil, true, 0, 0, false,
				ContainSubstring("sbom.json... OK\n")),
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
			Entry("errors limit forwarded",
				"/tmp/sbom.json", ispras.FormatContainer, RunOptions{Errors: 10},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "container", "--errors", "10", "/sbom/input.json",
				}),
			Entry("verbose forwarded",
				"/tmp/sbom.json", ispras.FormatOSS, RunOptions{Verbose: true},
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/input.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--verbose", "/sbom/input.json",
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
			Entry("zero errors limit", RunOptions{Errors: 0}),
			Entry("positive errors limit", RunOptions{Errors: 10}),
		)

		DescribeTable("rejects negative errors limit",
			func(opts RunOptions) {
				Expect(opts.Validate()).To(MatchError(ContainSubstring("--errors cannot be negative")))
			},
			Entry("negative errors", RunOptions{Errors: -1}),
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
