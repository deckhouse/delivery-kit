package checker

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

var _ = Describe("checker", func() {
	Describe("parseSingleResult", func() {
		DescribeTable("parses output correctly",
			func(out, path string, isprasFormat IsprasFormat, matcher types.GomegaMatcher) {
				err := parseSingleResult(context.Background(), out, path, isprasFormat)
				Expect(err).To(matcher)
			},
			Entry("no errors no warnings",
				"файл корректный\n", "/tmp/valid.json", IsprasFormatOSS,
				Succeed()),
			Entry("empty output",
				"", "/tmp/empty.json", IsprasFormatOSS,
				Succeed()),
			Entry("errors only",
				"ERROR: missing bomFormat\nERROR: missing specVersion\n", "/tmp/bad.json", IsprasFormatOSS,
				MatchError(ContainSubstring("validation failed for bad.json"))),
			Entry("warnings only",
				"WARNING: vcs url not found for pkg1\nWARNING: vcs url not found for pkg2\n", "/tmp/warn.json", IsprasFormatContainer,
				MatchError(ContainSubstring("validation failed for warn.json"))),
			Entry("errors and warnings",
				"ERROR: bad field\nWARNING: vcs issue\n", "/tmp/mixed.json", IsprasFormatOSS,
				MatchError(ContainSubstring("validation failed for mixed.json"))),
			Entry("non-prefixed output only",
				"some random output\nanother line\n", "/tmp/random.json", IsprasFormatOSS,
				Succeed()),
			Entry("errors mixed with non-prefixed lines",
				"starting check\nERROR: bad field\ndone\n", "/data/sbom/report.json", IsprasFormatOSS,
				MatchError(ContainSubstring("validation failed for report.json"))),
			Entry("uses basename from path",
				"", "/very/deep/nested/path/to/file.json", IsprasFormatOSS,
				Succeed()),
		)
	})

	Describe("parseMultiResult", func() {
		DescribeTable("parses multi-file output",
			func(out string, paths []string, isprasFormat IsprasFormat, wantPassed, wantFailed int, matcher types.GomegaMatcher) {
				passed, failed, err := parseMultiResult(context.Background(), out, paths, isprasFormat)
				Expect(passed).To(Equal(wantPassed))
				Expect(failed).To(Equal(wantFailed))
				Expect(err).To(matcher)
			},
			Entry("all pass",
				"===FILE:0===\nфайл корректный\n===FILE:1===\nфайл корректный\n",
				[]string{"/tmp/a.json", "/tmp/b.json"}, IsprasFormatOSS,
				2, 0, Succeed()),
			Entry("all fail with errors",
				"===FILE:0===\nERROR: bad format\n===FILE:1===\nERROR: missing field\n",
				[]string{"/tmp/a.json", "/tmp/b.json"}, IsprasFormatOSS,
				0, 2, MatchError(ContainSubstring("a.json"))),
			Entry("mixed results",
				"===FILE:0===\nфайл корректный\n===FILE:1===\nERROR: bad\n===FILE:2===\nall good\n",
				[]string{"/tmp/pass.json", "/tmp/fail.json", "/tmp/also_pass.json"}, IsprasFormatContainer,
				2, 1, MatchError(ContainSubstring("fail.json"))),
			Entry("warnings count as failures",
				"===FILE:0===\nWARNING: vcs not found\n===FILE:1===\nno issues\n",
				[]string{"/tmp/warned.json", "/tmp/ok.json"}, IsprasFormatOSS,
				1, 1, MatchError(ContainSubstring("warned.json"))),
			Entry("error message contains details",
				"===FILE:0===\nERROR: missing bomFormat\nERROR: missing specVersion\n",
				[]string{"/tmp/bad.json"}, IsprasFormatOSS,
				0, 1, MatchError(ContainSubstring("ERROR: missing bomFormat"))),
			Entry("file names extracted from paths",
				"===FILE:0===\nERROR: bad\n===FILE:1===\nERROR: also bad\n",
				[]string{"/deep/path/to/first.json", "/other/path/second.json"}, IsprasFormatOSS,
				0, 2, MatchError(ContainSubstring("first.json"))),
		)
	})

	Describe("multiFileScript", func() {
		DescribeTable("generates correct script",
			func(containerPaths []string, isprasFormat IsprasFormat, checkVCS bool, want string) {
				Expect(multiFileScript(containerPaths, isprasFormat, checkVCS)).To(Equal(want))
			},
			Entry("single file oss without check-vcs",
				[]string{"/sbom/0.json"}, IsprasFormatOSS, false,
				"echo '===FILE:0===' && python sbom-checker.py --format oss --errors 0 /sbom/0.json"),
			Entry("single file container with check-vcs",
				[]string{"/sbom/0.json"}, IsprasFormatContainer, true,
				"echo '===FILE:0===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/0.json"),
			Entry("multiple files separated by semicolon",
				[]string{"/sbom/0.json", "/sbom/1.json"}, IsprasFormatOSS, false,
				"echo '===FILE:0===' && python sbom-checker.py --format oss --errors 0 /sbom/0.json; echo '===FILE:1===' && python sbom-checker.py --format oss --errors 0 /sbom/1.json"),
			Entry("three files with check-vcs",
				[]string{"/sbom/0.json", "/sbom/1.json", "/sbom/2.json"}, IsprasFormatContainer, true,
				"echo '===FILE:0===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/0.json; echo '===FILE:1===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/1.json; echo '===FILE:2===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/2.json"),
		)
	})

	Describe("buildDockerArgs", func() {
		DescribeTable("builds correct docker arguments",
			func(paths []string, isprasFormat IsprasFormat, checkVCS bool, want []string) {
				got, err := buildDockerArgs(paths, isprasFormat, checkVCS)
				Expect(err).NotTo(HaveOccurred())
				Expect(got).To(Equal(want))
			},
			Entry("single file oss without check-vcs",
				[]string{"/tmp/sbom.json"}, IsprasFormatOSS, false,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/0.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "/sbom/0.json",
				}),
			Entry("single file with check-vcs",
				[]string{"/tmp/sbom.json"}, IsprasFormatOSS, true,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/0.json:ro",
					Image,
					"--format", "oss", "--errors", "0", "--check-vcs", "/sbom/0.json",
				}),
			Entry("single file container type",
				[]string{"/tmp/sbom.json"}, IsprasFormatContainer, false,
				[]string{
					"--rm",
					"-v", "/tmp/sbom.json:/sbom/0.json:ro",
					Image,
					"--format", "container", "--errors", "0", "/sbom/0.json",
				}),
			Entry("multiple files uses entrypoint",
				[]string{"/tmp/a.json", "/tmp/b.json"}, IsprasFormatOSS, false,
				[]string{
					"--rm",
					"-v", "/tmp/a.json:/sbom/0.json:ro",
					"-v", "/tmp/b.json:/sbom/1.json:ro",
					"--entrypoint", "sh", Image, "-c",
					multiFileScript([]string{"/sbom/0.json", "/sbom/1.json"}, IsprasFormatOSS, false),
				}),
			Entry("multiple files with check-vcs",
				[]string{"/tmp/a.json", "/tmp/b.json"}, IsprasFormatContainer, true,
				[]string{
					"--rm",
					"-v", "/tmp/a.json:/sbom/0.json:ro",
					"-v", "/tmp/b.json:/sbom/1.json:ro",
					"--entrypoint", "sh", Image, "-c",
					multiFileScript([]string{"/sbom/0.json", "/sbom/1.json"}, IsprasFormatContainer, true),
				}),
		)
	})
})
