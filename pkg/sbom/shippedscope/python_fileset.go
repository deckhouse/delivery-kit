package shippedscope

import (
	"encoding/csv"
	"io"
	"path"
	"strings"
)

const distInfoRecordSuffix = ".dist-info/RECORD"

// pythonFilesets draws every distribution's boundary from the paths its RECORD declares.
// A directory would be the wrong boundary: PEP 420 namespace packages let several
// distributions write into one directory, and a distribution's code rarely sits in a
// directory named after it.
//
// Names are normalised the PEP 503 way, so a fileset of "PyYAML" is named "pyyaml".
func pythonFilesets(index *FileIndex, manifests map[string][]byte) []Fileset {
	var filesets []Fileset

	pycache := compiledSources(index)

	for manifest, body := range manifests {
		if !strings.HasSuffix(manifest, distInfoRecordSuffix) {
			continue
		}

		distInfo := path.Dir(manifest)
		name, version, ok := strings.Cut(strings.TrimSuffix(path.Base(distInfo), ".dist-info"), "-")
		if !ok {
			continue
		}

		siteDir := path.Dir(distInfo)

		var declared []string
		for _, record := range recordPaths(body) {
			file := rootedJoin(siteDir, record)
			declared = append(declared, file)
			declared = append(declared, pycache[file]...)
		}

		files, symlinks := collect(index, declared)

		filesets = append(filesets, Fileset{
			Ecosystem: EcosystemPython,
			Name:      normalizePythonName(name),
			Version:   version,
			Root:      distInfo,
			Files:     files,
			Symlinks:  symlinks,
		})
	}

	return filesets
}

func recordPaths(body []byte) []string {
	reader := csv.NewReader(strings.NewReader(string(body)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	var paths []string
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}

			continue
		}

		if len(record) == 0 || record[0] == "" {
			continue
		}

		paths = append(paths, record[0])
	}

	return paths
}

// compiledSources maps a source file to the bytecode compiled from it. A RECORD never
// declares bytecode an installer did not write, and an image that ran compileall — or that
// dropped the sources afterwards — holds it all the same.
func compiledSources(index *FileIndex) map[string][]string {
	compiled := make(map[string][]string)

	for file := range index.Files {
		if !strings.HasSuffix(file, ".pyc") {
			continue
		}

		dir := path.Dir(file)
		if path.Base(dir) != "__pycache__" {
			continue
		}

		stem, _, _ := strings.Cut(path.Base(file), ".")
		source := path.Join(path.Dir(dir), stem+".py")
		compiled[source] = append(compiled[source], file)
	}

	return compiled
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
