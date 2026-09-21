package managedinput

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"strings"

	"golang.org/x/mod/module"
)

const (
	goDefaultHome   = "/root"
	goPathSuffix    = "go"
	goModCacheInDir = "pkg/mod"
)

// GoModCacheDir resolves the Go module cache directory the way the go tool does inside
// the image: $GOMODCACHE, else $GOPATH/pkg/mod, else $HOME/go/pkg/mod. imageEnv is the
// image config environment (KEY=VALUE entries); overlay (the packages directive env) takes
// precedence over it, matching how the install command sees the environment. syft's
// go-module-file-cataloger looks for module licenses under exactly this directory of the
// scanned filesystem.
func GoModCacheDir(imageEnv []string, overlay map[string]string) string {
	vars := envMap(imageEnv)
	for name, value := range overlay {
		vars[name] = value
	}

	if modCache := vars["GOMODCACHE"]; modCache != "" {
		return path.Clean(modCache)
	}

	goPath := vars["GOPATH"]
	if goPath == "" {
		home := vars["HOME"]
		if home == "" {
			home = goDefaultHome
		}
		goPath = path.Join(home, goPathSuffix)
	}
	// GOPATH is a list; the module cache lives in its first element.
	goPath = strings.SplitN(goPath, ":", 2)[0]

	return path.Join(goPath, goModCacheInDir)
}

func envMap(env []string) map[string]string {
	vars := make(map[string]string, len(env))
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		vars[key] = value
	}
	return vars
}

// GoModCacheModuleDirs lists, for every module recorded in a go.sum, its directory
// relative to the module cache root: <escaped module path>@<version>. Both the h1: line and
// the /go.mod line of a module map to the same directory, so the result is deduplicated
// and keeps first-seen order.
func GoModCacheModuleDirs(goSum []byte) ([]string, error) {
	var dirs []string
	seen := map[string]struct{}{}

	scanner := bufio.NewScanner(bytes.NewReader(goSum))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		modPath, version := fields[0], strings.TrimSuffix(fields[1], "/go.mod")

		escapedPath, err := module.EscapePath(modPath)
		if err != nil {
			return nil, fmt.Errorf("escape module path %q: %w", modPath, err)
		}
		escapedVersion, err := module.EscapeVersion(version)
		if err != nil {
			return nil, fmt.Errorf("escape module version %q of %q: %w", version, modPath, err)
		}

		dir := escapedPath + "@" + escapedVersion
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}

	return dirs, nil
}
