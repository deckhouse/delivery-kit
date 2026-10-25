package build

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/werf/werf/v3/pkg/image"
	"github.com/werf/werf/v3/pkg/sbom/managedinput"
	"github.com/werf/werf/v3/pkg/sbom/scanner"
	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

func (step *sbomStep) scanInstalledPackages(ctx context.Context, imageInfo *image.Info, scanOpts scanner.ScanOptions, index *shippedscope.FileIndex, targetPlatform string) ([]*cdx.BOM, error) {
	files := shippedscope.InstalledPackageFiles(ctx, index)
	catalogers := []struct {
		ecosystem shippedscope.Ecosystem
		name      string
		language  string
	}{
		{shippedscope.EcosystemPython, "python-installed-package-cataloger", "Python"},
		{shippedscope.EcosystemJavaScript, "javascript-package-cataloger", "JavaScript"},
		{shippedscope.EcosystemLua, "lua-rock-cataloger", "Lua"},
	}

	var boms []*cdx.BOM
	for _, entry := range catalogers {
		paths := files[entry.ecosystem]
		if len(paths) == 0 {
			continue
		}
		cataloger := scanner.Cataloger{Name: entry.name, SourceLang: entry.language}
		dir, cleanup, err := managedinput.MaterializeInstalledFiles(ctx, step.containerBackend, imageInfo.Name, paths, targetPlatform)
		if err != nil {
			return nil, fmt.Errorf("materialize installed package metadata for %q: %w", entry.name, err)
		}
		if entry.ecosystem == shippedscope.EcosystemLua {
			if err := rewriteInstalledRockspecs(dir, paths); err != nil {
				cleanup(ctx)
				return nil, err
			}
		}
		bom, _, err := step.scanCatalogerDir(ctx, scanOpts, cataloger, dir, imageInfo.Name, targetPlatform)
		cleanup(ctx)
		if err != nil {
			return nil, err
		}

		// Installed metadata does not identify which extras or runtime environment a
		// project selected. Keep dependency attribution in the declaration/lock scans.
		bom.Dependencies = nil
		boms = append(boms, bom)
	}

	return boms, nil
}

// Syft discards a whole rockspec when it meets a conditional statement or a boolean
// expression, which upstream rockspecs use to choose a source branch or tag. Such lines
// never carry the name, version or license, so they are dropped before the scan. The
// install directory supplies the name and version for rockspecs that compute them; they
// lead the file because Syft ignores every top-level field after the build table.
func rewriteInstalledRockspecs(dir string, paths map[string]string) error {
	for logicalPath := range paths {
		if !strings.HasSuffix(logicalPath, ".rockspec") {
			continue
		}
		file := filepath.Join(dir, filepath.Clean("/"+logicalPath))
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read installed rockspec %s: %w", logicalPath, err)
		}
		versionDir := path.Dir(logicalPath)
		data = syftParsableRockspec(data, path.Base(path.Dir(versionDir)), path.Base(versionDir))
		if err := os.WriteFile(file, data, 0o644); err != nil {
			return fmt.Errorf("write installed rockspec %s: %w", logicalPath, err)
		}
	}
	return nil
}

func syftParsableRockspec(data []byte, name, version string) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "package = %q\nversion = %q\n", name, version)
	longClose := ""
	blockDepth := 0
	for _, line := range strings.SplitAfter(string(data), "\n") {
		code := luaCode(line, &longClose)
		words := strings.FieldsFunc(code, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_'
		})
		if blockDepth > 0 || (len(words) > 0 && words[0] == "if") {
			for _, word := range words {
				switch word {
				case "if", "function", "do":
					blockDepth++
				case "end":
					blockDepth--
				}
			}
			blockDepth = max(blockDepth, 0)
			continue
		}
		if strings.Contains(code, "==") || strings.Contains(code, "~=") || slices.ContainsFunc(words, func(word string) bool {
			return word == "and" || word == "or" || word == "not"
		}) {
			continue
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

// luaCode returns the part of a line outside string literals and comments. longClose
// carries an unterminated long string or comment over to the next line.
func luaCode(line string, longClose *string) string {
	var code strings.Builder
	for i := 0; i < len(line); {
		if *longClose != "" {
			end := strings.Index(line[i:], *longClose)
			if end < 0 {
				return code.String()
			}
			i += end + len(*longClose)
			*longClose = ""
			continue
		}
		c := line[i]
		switch {
		case strings.HasPrefix(line[i:], "--"):
			if closer, ok := longBracketCloser(line[i+2:]); ok {
				*longClose = closer
				i += 2 + len(closer)
				continue
			}
			return code.String()
		case c == '"' || c == '\'':
			i++
			for i < len(line) && line[i] != c {
				if line[i] == '\\' {
					i++
				}
				i++
			}
			i++
			code.WriteByte(' ')
		case c == '[':
			if closer, ok := longBracketCloser(line[i:]); ok {
				*longClose = closer
				i += len(closer)
				continue
			}
			code.WriteByte(c)
			i++
		default:
			code.WriteByte(c)
			i++
		}
	}
	return code.String()
}

func longBracketCloser(s string) (string, bool) {
	if !strings.HasPrefix(s, "[") {
		return "", false
	}
	level := len(s[1:]) - len(strings.TrimLeft(s[1:], "="))
	if !strings.HasPrefix(s[1+level:], "[") {
		return "", false
	}
	return "]" + strings.Repeat("=", level) + "]", true
}
