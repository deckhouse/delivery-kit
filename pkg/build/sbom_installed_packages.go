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

// The scan copy omits conditionals and boolean fields that Syft cannot parse. These
// are not evaluated, so their metadata stays unknown. Directory-backed identity leads
// the file because Syft ignores top-level fields after the build table.
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
	var quote byte
	blockDepth := 0
	lines := strings.SplitAfter(string(data), "\n")
	for i, line := range lines {
		code := luaCode(line, &longClose, &quote)
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
			if len(words) == 0 || words[0] != "local" || i+1 >= len(lines) || !syftSkipsLocalBoolean(line, lines[i+1]) {
				continue
			}
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

// Syft keeps literal local values and skips a final unquoted expression. The skip
// consumes its newline, so a following blank line is needed to terminate the declaration.
func syftSkipsLocalBoolean(line, nextLine string) bool {
	if !strings.HasPrefix(strings.TrimLeft(nextLine, " \t"), "\n") && !strings.HasPrefix(strings.TrimLeft(nextLine, " \t"), "\r") {
		return false
	}
	left, value, ok := strings.Cut(line, "=")
	if !ok {
		return false
	}
	names := strings.Split(strings.TrimPrefix(strings.TrimSpace(left), "local"), ",")
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' }) >= 0 {
			return false
		}
	}
	for count := 1; ; count++ {
		value = strings.TrimLeft(value, " \t")
		if value == "" {
			return false
		}
		if value[0] != '"' && value[0] != '\'' {
			for {
				value = strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == ']' })
				if !strings.HasPrefix(value, "[") {
					return count == len(names) && value != ""
				}
				if len(value) < 3 {
					return false
				}
				close := value[1]
				if close == '[' {
					close = ']'
				} else if close != '"' && close != '\'' {
					return false
				}
				end := strings.IndexByte(value[2:], close)
				if end < 0 || end+3 >= len(value) || value[end+3] != ']' {
					return false
				}
				value = value[end+4:]
			}
		}
		end := strings.IndexByte(value[1:], value[0])
		if end < 0 {
			return false
		}
		value = strings.TrimLeft(value[end+2:], " \t")
		if !strings.HasPrefix(value, ",") {
			return false
		}
		value = value[1:]
	}
}

func luaCode(line string, longClose *string, quote *byte) string {
	var code strings.Builder
	for i := 0; i < len(line); {
		if *quote != 0 {
			switch line[i] {
			case '\\':
				i += 2
			case *quote:
				*quote = 0
				i++
			default:
				i++
			}
			continue
		}
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
			*quote = c
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
