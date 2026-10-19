package shippedscope

import (
	"context"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/logboek"
)

const rockManifestName = "rock_manifest"

// luaFilesets draws a rock's boundary from its rock manifest. The rock's own directory
// holds little more than the rockspec and its docs: luarocks spreads the code that runs
// over trees shared with every other rock, and only the manifest says which files there
// are this rock's.
func luaFilesets(ctx context.Context, index *FileIndex, manifests map[string][]byte) []Fileset {
	var filesets []Fileset

	for _, manifest := range slices.Sorted(maps.Keys(manifests)) {
		body := manifests[manifest]
		if path.Base(manifest) != rockManifestName {
			continue
		}

		rockDir := path.Dir(manifest)
		version := path.Base(rockDir)
		name := path.Base(path.Dir(rockDir))

		prefix, luaVersion, ok := luarocksTree(rockDir)
		if !ok {
			continue
		}

		sections := parseRockManifest(body)
		if len(sections) == 0 {
			logboek.Context(ctx).Debug().LogF("skip %s: not the table luarocks writes\n", manifest)

			continue
		}

		roots := map[string]string{
			"bin": path.Join(prefix, "bin"),
			"lib": path.Join(prefix, "lib", "lua", luaVersion),
			"lua": path.Join(prefix, "share", "lua", luaVersion),
		}

		var declared []string
		for section, entry := range sections {
			root, ok := roots[section]
			if !ok {
				// Everything else — the rockspec, doc, conf — stays in the rock's own
				// directory, as a file or a directory under the section's name.
				root = path.Join(rockDir, section)
			}

			declared = append(declared, manifestEntryPaths(root, entry)...)
		}

		files, symlinks := collect(index, declared)

		filesets = append(filesets, Fileset{
			Ecosystem:     EcosystemLua,
			Name:          name,
			Version:       version,
			Files:         files,
			Symlinks:      symlinks,
			DeclaresFiles: len(declared) > 0,
		})
	}

	return filesets
}

// manifestEntryPaths walks the nested tables a manifest uses for directories, down to the
// entries that name a file.
func manifestEntryPaths(prefix string, entry any) []string {
	table, ok := entry.(map[string]any)
	if !ok {
		return []string{rootedPath(prefix)}
	}

	var paths []string
	for key, value := range table {
		paths = append(paths, manifestEntryPaths(path.Join(prefix, key), value)...)
	}

	return paths
}

// luarocksTree splits a rock directory into the prefix the install roots hang off and the
// Lua version whose tree the rock was installed into: one image can carry several. The
// unversioned tree LuaRocks 2 wrote keeps the Lua version in its config instead, and is
// not read.
func luarocksTree(rockDir string) (string, string, bool) {
	marker := "/lib/luarocks/rocks-"

	start := strings.LastIndex(rockDir, marker)
	if start < 0 {
		return "", "", false
	}

	rest := rockDir[start+len(marker):]
	luaVersion, _, ok := strings.Cut(rest, "/")
	if !ok || luaVersion == "" {
		return "", "", false
	}

	return rockDir[:start], luaVersion, true
}

// parseRockManifest reads the Lua table luarocks writes: nested tables of string keys and
// string values, and nothing else of the language.
func parseRockManifest(body []byte) map[string]any {
	text := string(body)

	start := strings.Index(text, "{")
	if start < 0 {
		return nil
	}

	table, _, ok := parseLuaTable(text[start:])
	if !ok {
		return nil
	}

	return table
}

func parseLuaTable(text string) (map[string]any, int, bool) {
	if len(text) == 0 || text[0] != '{' {
		return nil, 0, false
	}

	table := make(map[string]any)

	position := 1
	for position < len(text) {
		switch {
		case isLuaSpace(text[position]), text[position] == ',', text[position] == ';':
			position++

			continue
		case text[position] == '}':
			return table, position + 1, true
		}

		key, consumed, ok := parseLuaKey(text[position:])
		if !ok {
			return nil, 0, false
		}
		position += consumed

		for position < len(text) && isLuaSpace(text[position]) {
			position++
		}
		if position >= len(text) || text[position] != '=' {
			return nil, 0, false
		}
		position++

		for position < len(text) && isLuaSpace(text[position]) {
			position++
		}
		if position >= len(text) {
			return nil, 0, false
		}

		if text[position] == '{' {
			nested, consumed, ok := parseLuaTable(text[position:])
			if !ok {
				return nil, 0, false
			}

			table[key] = nested
			position += consumed

			continue
		}

		value, consumed, ok := parseLuaString(text[position:])
		if !ok {
			return nil, 0, false
		}

		table[key] = value
		position += consumed
	}

	return nil, 0, false
}

func parseLuaKey(text string) (string, int, bool) {
	if text[0] == '[' {
		value, consumed, ok := parseLuaString(text[1:])
		if !ok {
			return "", 0, false
		}

		position := 1 + consumed
		for position < len(text) && isLuaSpace(text[position]) {
			position++
		}
		if position >= len(text) || text[position] != ']' {
			return "", 0, false
		}

		return value, position + 1, true
	}

	end := 0
	for end < len(text) && (isLuaNameChar(text[end])) {
		end++
	}
	if end == 0 {
		return "", 0, false
	}

	return text[:end], end, true
}

// parseLuaString reads a string the way luarocks writes one: %q-quoted, so a quote, a
// backslash and a newline inside it come escaped.
func parseLuaString(text string) (string, int, bool) {
	if len(text) == 0 || (text[0] != '"' && text[0] != '\'') {
		return "", 0, false
	}

	quote := text[0]

	var value strings.Builder
	for position := 1; position < len(text); position++ {
		switch text[position] {
		case '\\':
			position++
			if position >= len(text) {
				return "", 0, false
			}

			value.WriteByte(text[position])
		case quote:
			return value.String(), position + 1, true
		default:
			value.WriteByte(text[position])
		}
	}

	return "", 0, false
}

func isLuaSpace(char byte) bool {
	return char == ' ' || char == '\t' || char == '\n' || char == '\r'
}

func isLuaNameChar(char byte) bool {
	return char == '_' ||
		(char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9')
}
