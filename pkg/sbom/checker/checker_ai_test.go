//go:build ai_tests

package checker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAI_parseSingleResult(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		out       string
		path      string
		sbomType  SbomType
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "no errors no warnings",
			out:      "файл корректный\n",
			path:     "/tmp/valid.json",
			sbomType: SbomTypeOSS,
			wantErr:  false,
		},
		{
			name:     "empty output",
			out:      "",
			path:     "/tmp/empty.json",
			sbomType: SbomTypeOSS,
			wantErr:  false,
		},
		{
			name:      "errors only",
			out:       "ERROR: missing bomFormat\nERROR: missing specVersion\n",
			path:      "/tmp/bad.json",
			sbomType:  SbomTypeOSS,
			wantErr:   true,
			errSubstr: "validation failed for bad.json",
		},
		{
			name:      "warnings only",
			out:       "WARNING: vcs url not found for pkg1\nWARNING: vcs url not found for pkg2\n",
			path:      "/tmp/warn.json",
			sbomType:  SbomTypeContainer,
			wantErr:   true,
			errSubstr: "validation failed for warn.json",
		},
		{
			name:      "errors and warnings",
			out:       "ERROR: bad field\nWARNING: vcs issue\n",
			path:      "/tmp/mixed.json",
			sbomType:  SbomTypeOSS,
			wantErr:   true,
			errSubstr: "validation failed for mixed.json",
		},
		{
			name:     "non-prefixed output only",
			out:      "some random output\nanother line\n",
			path:     "/tmp/random.json",
			sbomType: SbomTypeOSS,
			wantErr:  false,
		},
		{
			name:      "errors mixed with non-prefixed lines",
			out:       "starting check\nERROR: bad field\ndone\n",
			path:      "/data/sbom/report.json",
			sbomType:  SbomTypeOSS,
			wantErr:   true,
			errSubstr: "validation failed for report.json",
		},
		{
			name:     "uses basename from path",
			out:      "",
			path:     "/very/deep/nested/path/to/file.json",
			sbomType: SbomTypeOSS,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSingleResult(ctx, tt.out, tt.path, tt.sbomType)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAI_parseMultiResult(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		out        string
		paths      []string
		sbomType   SbomType
		wantPassed int
		wantFailed int
		wantErr    bool
		errSubstr  string
	}{
		{
			name:       "all pass",
			out:        "===FILE:0===\nфайл корректный\n===FILE:1===\nфайл корректный\n",
			paths:      []string{"/tmp/a.json", "/tmp/b.json"},
			sbomType:   SbomTypeOSS,
			wantPassed: 2,
			wantFailed: 0,
			wantErr:    false,
		},
		{
			name:       "all fail with errors",
			out:        "===FILE:0===\nERROR: bad format\n===FILE:1===\nERROR: missing field\n",
			paths:      []string{"/tmp/a.json", "/tmp/b.json"},
			sbomType:   SbomTypeOSS,
			wantPassed: 0,
			wantFailed: 2,
			wantErr:    true,
			errSubstr:  "a.json",
		},
		{
			name:       "mixed results",
			out:        "===FILE:0===\nфайл корректный\n===FILE:1===\nERROR: bad\n===FILE:2===\nall good\n",
			paths:      []string{"/tmp/pass.json", "/tmp/fail.json", "/tmp/also_pass.json"},
			sbomType:   SbomTypeContainer,
			wantPassed: 2,
			wantFailed: 1,
			wantErr:    true,
			errSubstr:  "fail.json",
		},
		{
			name:       "warnings count as failures",
			out:        "===FILE:0===\nWARNING: vcs not found\n===FILE:1===\nno issues\n",
			paths:      []string{"/tmp/warned.json", "/tmp/ok.json"},
			sbomType:   SbomTypeOSS,
			wantPassed: 1,
			wantFailed: 1,
			wantErr:    true,
			errSubstr:  "warned.json",
		},
		{
			name:       "error message contains details",
			out:        "===FILE:0===\nERROR: missing bomFormat\nERROR: missing specVersion\n",
			paths:      []string{"/tmp/bad.json"},
			sbomType:   SbomTypeOSS,
			wantPassed: 0,
			wantFailed: 1,
			wantErr:    true,
			errSubstr:  "ERROR: missing bomFormat",
		},
		{
			name:       "file names extracted from paths",
			out:        "===FILE:0===\nERROR: bad\n===FILE:1===\nERROR: also bad\n",
			paths:      []string{"/deep/path/to/first.json", "/other/path/second.json"},
			sbomType:   SbomTypeOSS,
			wantPassed: 0,
			wantFailed: 2,
			wantErr:    true,
			errSubstr:  "first.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passed, failed, err := parseMultiResult(ctx, tt.out, tt.paths, tt.sbomType)
			assert.Equal(t, tt.wantPassed, passed)
			assert.Equal(t, tt.wantFailed, failed)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAI_multiFileScript(t *testing.T) {
	tests := []struct {
		name           string
		containerPaths []string
		sbomType       SbomType
		checkVCS       bool
		want           string
	}{
		{
			name:           "single file oss without check-vcs",
			containerPaths: []string{"/sbom/0.json"},
			sbomType:       SbomTypeOSS,
			checkVCS:       false,
			want:           "echo '===FILE:0===' && python sbom-checker.py --format oss --errors 0 /sbom/0.json",
		},
		{
			name:           "single file container with check-vcs",
			containerPaths: []string{"/sbom/0.json"},
			sbomType:       SbomTypeContainer,
			checkVCS:       true,
			want:           "echo '===FILE:0===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/0.json",
		},
		{
			name:           "multiple files separated by semicolon",
			containerPaths: []string{"/sbom/0.json", "/sbom/1.json"},
			sbomType:       SbomTypeOSS,
			checkVCS:       false,
			want:           "echo '===FILE:0===' && python sbom-checker.py --format oss --errors 0 /sbom/0.json; echo '===FILE:1===' && python sbom-checker.py --format oss --errors 0 /sbom/1.json",
		},
		{
			name:           "three files with check-vcs",
			containerPaths: []string{"/sbom/0.json", "/sbom/1.json", "/sbom/2.json"},
			sbomType:       SbomTypeContainer,
			checkVCS:       true,
			want:           "echo '===FILE:0===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/0.json; echo '===FILE:1===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/1.json; echo '===FILE:2===' && python sbom-checker.py --format container --errors 0 --check-vcs /sbom/2.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := multiFileScript(tt.containerPaths, tt.sbomType, tt.checkVCS)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAI_buildDockerArgs(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		sbomType SbomType
		checkVCS bool
		want     []string
	}{
		{
			name:     "single file oss without check-vcs",
			paths:    []string{"/tmp/sbom.json"},
			sbomType: SbomTypeOSS,
			checkVCS: false,
			want: []string{
				"--rm",
				"-v", "/tmp/sbom.json:/sbom/0.json:ro",
				Image,
				"--format", "oss", "--errors", "0", "/sbom/0.json",
			},
		},
		{
			name:     "single file with check-vcs",
			paths:    []string{"/tmp/sbom.json"},
			sbomType: SbomTypeOSS,
			checkVCS: true,
			want: []string{
				"--rm",
				"-v", "/tmp/sbom.json:/sbom/0.json:ro",
				Image,
				"--format", "oss", "--errors", "0", "--check-vcs", "/sbom/0.json",
			},
		},
		{
			name:     "single file container type",
			paths:    []string{"/tmp/sbom.json"},
			sbomType: SbomTypeContainer,
			checkVCS: false,
			want: []string{
				"--rm",
				"-v", "/tmp/sbom.json:/sbom/0.json:ro",
				Image,
				"--format", "container", "--errors", "0", "/sbom/0.json",
			},
		},
		{
			name:     "multiple files uses entrypoint",
			paths:    []string{"/tmp/a.json", "/tmp/b.json"},
			sbomType: SbomTypeOSS,
			checkVCS: false,
			want: []string{
				"--rm",
				"-v", "/tmp/a.json:/sbom/0.json:ro",
				"-v", "/tmp/b.json:/sbom/1.json:ro",
				"--entrypoint", "sh", Image, "-c",
				multiFileScript([]string{"/sbom/0.json", "/sbom/1.json"}, SbomTypeOSS, false),
			},
		},
		{
			name:     "multiple files with check-vcs",
			paths:    []string{"/tmp/a.json", "/tmp/b.json"},
			sbomType: SbomTypeContainer,
			checkVCS: true,
			want: []string{
				"--rm",
				"-v", "/tmp/a.json:/sbom/0.json:ro",
				"-v", "/tmp/b.json:/sbom/1.json:ro",
				"--entrypoint", "sh", Image, "-c",
				multiFileScript([]string{"/sbom/0.json", "/sbom/1.json"}, SbomTypeContainer, true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildDockerArgs(tt.paths, tt.sbomType, tt.checkVCS)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
