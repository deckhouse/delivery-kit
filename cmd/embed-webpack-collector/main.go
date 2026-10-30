// Command embed-webpack-collector packs the runtime of the private Webpack evidence
// collector - the CommonJS files `activate.cjs` reaches and the production dependency
// closure it loads them with - into the deterministic archive the werf binary embeds.
//
// The archive is generated rather than committed: the dependencies live in an
// npm-installed node_modules that no repository of this project carries. They are not
// read from such an install either. The lockfile states which distribution each
// installed path holds, and that distribution is what this fetches and verifies against
// the locked integrity, so the machine that builds a release needs the collector's
// lockfile and the registry, not a working npm.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// fetchTimeout bounds one distribution download. A release build that cannot reach the
// registry fails rather than embedding a collector it could not verify.
const fetchTimeout = 120 * time.Second

// registry is the one host a locked distribution may come from. The lockfile states it
// for every package of this closure, and a redirect away from it is refused: bytes are
// held against the locked integrity, but where they were asked for is settled here.
const registry = "registry.npmjs.org"

// maxDistributionSize bounds one downloaded distribution. The packages of this closure
// are hundreds of kilobytes; a response of another order is not one of them.
const maxDistributionSize = 64 << 20

// entry is one packed file: where it stands in the archive and what it holds.
type entry struct {
	name string
	body []byte
}

// excluded names what the collector's own directory holds beside its runtime: the
// specs, their fixtures and the producer patches of the esbuild tool input. A runtime
// file reaching one of them would be an error, not something to pack.
func excluded(name string) bool {
	base := path.Base(name)

	return strings.HasSuffix(base, ".test.cjs") || strings.Contains(base, "fixture") ||
		strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, "esbuild/") ||
		strings.Contains(name, "fixtures/")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "embed-webpack-collector: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	source := os.Getenv("DK_WEBPACK_COLLECTOR_SOURCE")
	if source == "" {
		source = filepath.Join("pkg", "sbom", "webpack")
	}
	embedRoot := os.Getenv("DK_WEBPACK_COLLECTOR_EMBED_ROOT")
	if embedRoot == "" {
		embedRoot = filepath.Join("pkg", "sbom", "webpackcollector", "embed")
	}

	runtime, err := runtimeClosure(source)
	if err != nil {
		return err
	}
	dependencies, err := dependencyClosure(filepath.Join(source, "package-lock.json"))
	if err != nil {
		return err
	}
	entries := slices.Concat(runtime, dependencies)
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	gzipped, digest, err := buildArchive(entries)
	if err != nil {
		return err
	}
	if err := write(embedRoot, gzipped, digest); err != nil {
		return err
	}
	fmt.Printf("Embedded the SBOM webpack collector: %d files, sha256 %s\n", len(entries), digest)

	return nil
}

// runtimeClosure is every CommonJS file of the collector that `activate.cjs` can
// reach. A resolver the activation selects by lockfile name is named as a plain
// string literal rather than required outright, so literals are followed too.
func runtimeClosure(source string) ([]entry, error) {
	var entries []entry
	seen := map[string]bool{}
	queue := []string{"activate.cjs"}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		if excluded(name) {
			return nil, fmt.Errorf("runtime file %s is a spec, a fixture or a tool input, which the collector runtime must not reach", name)
		}
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("read collector runtime: %w", err)
		}
		entries = append(entries, entry{name: name, body: body})
		for _, literal := range literals(body) {
			if !strings.HasPrefix(literal, "./") || !strings.HasSuffix(literal, ".cjs") {
				continue
			}
			required := path.Join(path.Dir(name), literal)
			if required == ".." || strings.HasPrefix(required, "../") {
				return nil, fmt.Errorf("%s names %s, which is outside the collector", name, literal)
			}
			queue = append(queue, required)
		}
	}

	return entries, nil
}

// literals are the string literals of a CommonJS source, with comments left out. A
// regular expression literal is not told from division here: the files this reads are
// the collector's own, and a tree missing a file a runtime file requires is what the
// extraction spec loads the whole packed tree to catch.
func literals(body []byte) []string {
	var found []string
	for i := 0; i < len(body); {
		switch {
		case body[i] == '/' && i+1 < len(body) && body[i+1] == '/':
			for i < len(body) && body[i] != '\n' {
				i++
			}
		case body[i] == '/' && i+1 < len(body) && body[i+1] == '*':
			i += 2
			for i+1 < len(body) && !(body[i] == '*' && body[i+1] == '/') {
				i++
			}
			i += 2
		case body[i] == '\'' || body[i] == '"' || body[i] == '`':
			quote := body[i]
			i++
			start := i
			for i < len(body) && body[i] != quote {
				if body[i] == '\\' {
					i++
				}
				i++
			}
			found = append(found, string(body[start:min(i, len(body))]))
			i++
		default:
			i++
		}
	}

	return found
}

// lockfile is what npm wrote about this install: which distribution stands at which
// installed path, and what each of them requires.
type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	// Dev and Optional mark a package no production install of this project holds.
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Dependencies map[string]string `json:"dependencies"`
	// OptionalDependencies and PeerDependencies are installs decided by the host
	// environment and by the rest of the tree, which this closure does not model.
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// dependencyClosure is the production dependency tree of the collector: every package
// the declared dependencies reach, resolved the way Node resolves it over the installed
// paths the lockfile states, fetched from the registry and verified against the locked
// integrity before a byte of it is packed.
func dependencyClosure(lockPath string) ([]entry, error) {
	body, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read the collector lockfile: %w", err)
	}
	var lock lockfile
	if err := json.Unmarshal(body, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", lockPath, err)
	}
	// Version 2 states the same install twice and version 1 states no integrity at
	// all; neither is the file this reads.
	if lock.LockfileVersion != 3 {
		return nil, fmt.Errorf("%s is lockfile version %d, and this reads version 3", lockPath, lock.LockfileVersion)
	}
	root, present := lock.Packages[""]
	if !present {
		return nil, fmt.Errorf("%s states no root package", lockPath)
	}

	client := &http.Client{Timeout: fetchTimeout, CheckRedirect: offRegistryRedirect}
	var entries []entry
	packed := map[string]bool{}
	type request struct{ name, from string }
	queue := make([]request, 0, len(root.Dependencies))
	for _, name := range sortedNames(root.Dependencies) {
		queue = append(queue, request{name: name})
	}
	for len(queue) > 0 {
		requested := queue[0]
		queue = queue[1:]
		installed, locked, err := resolveLocked(lock, requested.name, requested.from)
		if err != nil {
			return nil, err
		}
		if packed[installed] {
			continue
		}
		packed[installed] = true
		if locked.Dev || locked.Optional {
			return nil, fmt.Errorf("%s is locked as a development or optional install, which no production closure holds", installed)
		}
		if len(locked.OptionalDependencies) > 0 || len(locked.PeerDependencies) > 0 {
			return nil, fmt.Errorf("%s declares optional or peer dependencies, whose installs this closure does not resolve", installed)
		}
		for _, name := range sortedNames(locked.Dependencies) {
			queue = append(queue, request{name: name, from: installed})
		}
		files, err := distributionFiles(client, installed, locked)
		if err != nil {
			return nil, err
		}
		entries = append(entries, files...)
	}

	return entries, nil
}

func sortedNames(dependencies map[string]string) []string {
	names := make([]string, 0, len(dependencies))
	for name := range dependencies {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// resolveLocked finds the installed path a require of name from the package installed
// at from resolves to, walking the enclosing node_modules scopes the way Node does.
func resolveLocked(lock lockfile, name, from string) (string, lockPackage, error) {
	for scope, more := from, true; more; scope, more = parentScope(scope) {
		installed := path.Join(scope, "node_modules", name)
		if locked, present := lock.Packages[installed]; present {
			return installed, locked, nil
		}
	}

	return "", lockPackage{}, fmt.Errorf("the lockfile holds no install of %s for %s", name, path.Join(from, "node_modules"))
}

// parentScope is the installed path whose node_modules a package's own requires
// resolve from next, the root being the last of them.
func parentScope(installed string) (string, bool) {
	if installed == "" {
		return "", false
	}
	if nested := strings.LastIndex(installed, "/node_modules/"); nested >= 0 {
		return installed[:nested], true
	}

	return "", true
}

// offRegistryRedirect refuses a redirect that leaves the registry the lockfile pins.
// The bytes are held against the locked integrity either way; where they are asked for
// is settled here.
func offRegistryRedirect(request *http.Request, _ []*http.Request) error {
	if request.URL.Scheme != "https" || request.URL.Hostname() != registry {
		return fmt.Errorf("redirected to %s, which is not the registry the lockfile pins", request.URL.Redacted())
	}

	return nil
}

// distributionFiles is every ordinary file of one locked distribution, named by the
// path the package is installed at. The archive npm published is fetched and held
// against the integrity the lockfile states before it is read: a registry serving other
// bytes supplies nothing here.
func distributionFiles(client *http.Client, installed string, locked lockPackage) ([]entry, error) {
	location, err := url.Parse(locked.Resolved)
	if err != nil || location.Scheme != "https" || location.Hostname() != registry {
		return nil, fmt.Errorf("%s is locked to %q, which is not a distribution of %s this fetches", installed, locked.Resolved, registry)
	}
	response, err := client.Get(locked.Resolved)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", locked.Resolved, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", locked.Resolved, response.Status)
	}
	distribution, err := io.ReadAll(io.LimitReader(response.Body, maxDistributionSize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", locked.Resolved, err)
	}
	if len(distribution) > maxDistributionSize {
		return nil, fmt.Errorf("fetch %s: the distribution is larger than %d bytes", locked.Resolved, maxDistributionSize)
	}
	if err := checkIntegrity(distribution, locked.Integrity); err != nil {
		return nil, fmt.Errorf("%s from %s: %w", installed, locked.Resolved, err)
	}

	return unpackDistribution(distribution, installed)
}

// checkIntegrity holds bytes against the SRI the lockfile states. Only SHA-512 is
// read: it is what npm locks, and a weaker spelling beside it must not be what a
// distribution is accepted on.
func checkIntegrity(distribution []byte, integrity string) error {
	tokens := strings.Fields(integrity)
	if len(tokens) == 0 {
		return fmt.Errorf("the lockfile states no integrity")
	}
	sum := sha512.Sum512(distribution)
	actual := base64.StdEncoding.EncodeToString(sum[:])
	for _, token := range tokens {
		expected, found := strings.CutPrefix(token, "sha512-")
		if !found {
			return fmt.Errorf("integrity %q is not a SHA-512 token", token)
		}
		if expected != actual {
			return fmt.Errorf("integrity check failed: expected sha512 %s, got %s", expected, actual)
		}
	}

	return nil
}

// unpackDistribution reads the published archive into the files of one installed
// package. Every npm distribution holds its files under one directory; its name is
// whatever the publisher chose and says nothing, so it is dropped rather than trusted.
func unpackDistribution(distribution []byte, installed string) ([]entry, error) {
	reader, err := gzip.NewReader(bytes.NewReader(distribution))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", installed, err)
	}
	defer reader.Close()

	var entries []entry
	root := ""
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", installed, err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%s holds %s, which is not an ordinary file", installed, header.Name)
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		prefix, rest, nested := strings.Cut(name, "/")
		if !nested || prefix == ".." {
			return nil, fmt.Errorf("%s holds %s, which stands outside the published package", installed, header.Name)
		}
		if root == "" {
			root = prefix
		}
		if prefix != root {
			return nil, fmt.Errorf("%s holds %s beside %s, and a distribution is one package", installed, header.Name, root)
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", installed, err)
		}
		entries = append(entries, entry{name: path.Join(installed, rest), body: body})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s holds no files", installed)
	}

	return entries, nil
}

// buildArchive packs the tree and reports the SHA-256 of its uncompressed bytes. The
// archive states nothing of the machine that produced it: sorted names, one mode, no
// owner and no time, so that the same tree always embeds as the same digest.
func buildArchive(entries []entry) ([]byte, string, error) {
	var packed bytes.Buffer
	compressed := gzip.NewWriter(&packed)
	hasher := sha256.New()
	archive := tar.NewWriter(io.MultiWriter(compressed, hasher))
	for i, item := range entries {
		if i > 0 && entries[i-1].name == item.name {
			return nil, "", fmt.Errorf("%s is packed more than once", item.name)
		}
		header := &tar.Header{
			Name: item.name, Typeflag: tar.TypeReg, Mode: 0o644,
			Size: int64(len(item.body)), ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatPAX,
		}
		if err := archive.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if _, err := archive.Write(item.body); err != nil {
			return nil, "", err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, "", err
	}
	if err := compressed.Close(); err != nil {
		return nil, "", err
	}

	return packed.Bytes(), hex.EncodeToString(hasher.Sum(nil)), nil
}

func write(embedRoot string, gzipped []byte, digest string) error {
	if err := os.MkdirAll(embedRoot, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(embedRoot, "collector.tar.gz"), gzipped, 0o644); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(embedRoot, "collector.tar.sha256"), []byte(digest+"\n"), 0o644)
}
