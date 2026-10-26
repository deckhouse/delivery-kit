package shippedscope

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/werf/logboek"
)

const distInfoRecordSuffix = ".dist-info/RECORD"

// pythonFilesets draws every distribution's boundary from the paths its RECORD declares.
// A directory would be the wrong boundary: PEP 420 namespace packages let several
// distributions write into one directory, and a distribution's code rarely sits in a
// directory named after it.
//
// Names are normalised the PEP 503 way, so a fileset of "PyYAML" is named "pyyaml".
func pythonFilesets(ctx context.Context, index *FileIndex, manifests map[string][]byte) []Fileset {
	var filesets []Fileset

	bytecode := compiledSources(index)

	for _, manifest := range slices.Sorted(maps.Keys(manifests)) {
		body := manifests[manifest]
		if !strings.HasSuffix(manifest, distInfoRecordSuffix) {
			continue
		}

		distInfo := path.Dir(manifest)
		name, version, ok := strings.Cut(strings.TrimSuffix(path.Base(distInfo), ".dist-info"), "-")
		if !ok {
			continue
		}

		siteDir := path.Dir(distInfo)
		incomplete := false
		originPath := path.Join(distInfo, "direct_url.json")
		if origin, exists := manifests[originPath]; exists {
			incomplete = pythonOriginMayBeEditable(origin)
		} else if _, linked := index.Symlinks[originPath]; linked {
			incomplete = true
		}

		var declared []string
		for _, record := range recordPaths(ctx, manifest, body) {
			file := rootedJoin(siteDir, record)
			if strings.HasPrefix(path.Base(file), "__editable__") || strings.HasSuffix(file, ".egg-link") {
				incomplete = true
			}
			declared = append(declared, file)
			declared = append(declared, bytecode[file]...)
		}

		files, symlinks := collect(index, declared)

		filesets = append(filesets, Fileset{
			Ecosystem:     EcosystemPython,
			Name:          normalizePythonName(name),
			Version:       version,
			Files:         files,
			Symlinks:      symlinks,
			DeclaresFiles: len(declared) > 0,
			Incomplete:    incomplete,
		})
	}

	return filesets
}

func pythonOriginMayBeEditable(body []byte) bool {
	var origin map[string]json.RawMessage
	if err := json.Unmarshal(body, &origin); err != nil || origin == nil {
		return true
	}
	raw, exists := origin["dir_info"]
	if !exists {
		return false
	}
	var directory map[string]json.RawMessage
	if err := json.Unmarshal(raw, &directory); err != nil || directory == nil {
		return true
	}
	editable, exists := directory["editable"]
	return exists && strings.TrimSpace(string(editable)) != "false"
}

func recordPaths(ctx context.Context, manifest string, body []byte) []string {
	reader := csv.NewReader(strings.NewReader(string(body)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	var paths []string
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logboek.Context(ctx).Debug().LogF("skip a line of %s: %s\n", manifest, err)

			continue
		}

		if len(record) == 0 || record[0] == "" {
			continue
		}

		paths = append(paths, record[0])
	}

	return paths
}

// compiledSources associates bytecode paths with RECORD-declared source paths, including
// compileall output the installer never recorded. This establishes file ownership within
// the installation layout, not bytecode validity or freshness. PEP 552 source hashes are
// not comparable to RECORD hashes and cannot establish provenance after source removal.
func compiledSources(index *FileIndex) map[string][]string {
	compiled := make(map[string][]string)

	for file := range index.Files {
		if !strings.HasSuffix(file, ".pyc") {
			continue
		}

		dir := path.Dir(file)
		if path.Base(dir) != "__pycache__" {
			source := strings.TrimSuffix(file, ".pyc") + ".py"
			compiled[source] = append(compiled[source], file)
			continue
		}

		stem, ok := bytecodeStem(path.Base(file))
		if !ok {
			continue
		}

		source := path.Join(path.Dir(dir), stem+".py")
		compiled[source] = append(compiled[source], file)
	}

	return compiled
}

// bytecodeStem takes "<stem>.<interpreter tag>[.opt-N].pyc" apart from the right, because
// the stem itself may hold dots, and may spell anything the suffixes spell:
// "foo.bar.cpython-312.pyc" was compiled from "foo.bar.py", and so was
// "my.opt-config.cpython-312.pyc" from "my.opt-config.py".
func bytecodeStem(name string) (string, bool) {
	rest := strings.TrimSuffix(name, ".pyc")

	if tagged, last, ok := cutLast(rest, "."); ok && strings.HasPrefix(last, "opt-") {
		rest = tagged
	}

	stem, _, ok := cutLast(rest, ".")

	return stem, ok && stem != ""
}

func cutLast(text, separator string) (string, string, bool) {
	at := strings.LastIndex(text, separator)
	if at < 0 {
		return text, "", false
	}

	return text[:at], text[at+len(separator):], true
}

func normalizePythonName(name string) string {
	normalized := strings.Map(func(r rune) rune {
		if r == '_' || r == '.' {
			return '-'
		}

		return r
	}, strings.ToLower(name))

	for strings.Contains(normalized, "--") {
		normalized = strings.ReplaceAll(normalized, "--", "-")
	}

	return normalized
}
