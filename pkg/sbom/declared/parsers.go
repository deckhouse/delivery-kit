package declared

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/modfile"
)

// parseGoMod declares the direct requirements: every `require` without the
// `// indirect` marker. A module replaced by another one is declared under the
// replacement's path and version, since that is the module syft catalogs. A
// module replaced by a local directory is declared without a version — werf
// resolves it from the git history afterwards — under both its path and the
// directory, because syft names the component after the directory until that
// resolution renames it.
func parseGoMod(spec []byte) ([]Package, error) {
	mod, err := modfile.Parse("go.mod", spec, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	replaces := make(map[string][]Package, len(mod.Replace))
	for _, replace := range mod.Replace {
		key := replace.Old.Path
		if replace.Old.Version != "" {
			key += "@" + replace.Old.Version
		}
		replaces[key] = replaceTargets(replace)
	}

	var pkgs []Package
	for _, req := range mod.Require {
		if req.Indirect {
			continue
		}
		if targets, ok := replaces[req.Mod.Path+"@"+req.Mod.Version]; ok {
			pkgs = append(pkgs, targets...)
			continue
		}
		if targets, ok := replaces[req.Mod.Path]; ok {
			pkgs = append(pkgs, targets...)
			continue
		}
		pkgs = append(pkgs, Package{Name: req.Mod.Path, Version: req.Mod.Version})
	}

	return pkgs, nil
}

func replaceTargets(replace *modfile.Replace) []Package {
	if modfile.IsDirectoryPath(replace.New.Path) {
		return []Package{{Name: replace.Old.Path}, {Name: replace.New.Path}}
	}
	return []Package{{Name: replace.New.Path, Version: replace.New.Version}}
}

// parsePackageJSON declares `dependencies` and `devDependencies`. Versions in
// package.json are ranges, so none is declared.
func parsePackageJSON(spec []byte) ([]Package, error) {
	var manifest struct {
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if err := json.Unmarshal(spec, &manifest); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	pkgs := make([]Package, 0, len(manifest.Dependencies)+len(manifest.DevDependencies))
	for _, deps := range []map[string]json.RawMessage{manifest.Dependencies, manifest.DevDependencies} {
		for name := range deps {
			pkgs = append(pkgs, Package{Name: name})
		}
	}

	return sorted(pkgs), nil
}

// parseCargoToml declares `[dependencies]`. A dependency renamed with
// `package = "..."` is declared under the crate name. Versions in Cargo.toml
// are caret ranges, so none is declared.
func parseCargoToml(spec []byte) ([]Package, error) {
	var manifest struct {
		Dependencies map[string]toml.Primitive `toml:"dependencies"`
	}
	md, err := toml.Decode(string(spec), &manifest)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.toml: %w", err)
	}

	pkgs := make([]Package, 0, len(manifest.Dependencies))
	for name, prim := range manifest.Dependencies {
		var detailed struct {
			Package string `toml:"package"`
		}
		if err := md.PrimitiveDecode(prim, &detailed); err == nil && detailed.Package != "" {
			name = detailed.Package
		}
		pkgs = append(pkgs, Package{Name: name})
	}

	return sorted(pkgs), nil
}

// parsePyprojectToml declares `[project].dependencies` (PEP 621 requirement
// strings) and `[tool.poetry.dependencies]` (a name-to-constraint table, in
// which `python` constrains the interpreter rather than naming a package).
func parsePyprojectToml(spec []byte) ([]Package, error) {
	var manifest struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]toml.Primitive `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(spec), &manifest); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	var pkgs []Package
	for _, requirement := range manifest.Project.Dependencies {
		if pkg, ok := parseRequirement(requirement); ok {
			pkgs = append(pkgs, pkg)
		}
	}

	var poetry []Package
	for name := range manifest.Tool.Poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue
		}
		poetry = append(poetry, Package{Name: name})
	}

	return append(pkgs, sorted(poetry)...), nil
}

// parseRequirementsTxt declares every requirement line of a requirements.txt.
// Options (`-r`, `--index-url`, …), comments, blank lines and URL or path
// requirements are skipped: they name files or locations, not packages.
func parseRequirementsTxt(spec []byte) ([]Package, error) {
	var pkgs []Package
	scanner := bufio.NewScanner(bytes.NewReader(spec))
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if pkg, ok := parseRequirement(line); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse requirements.txt: %w", err)
	}

	return pkgs, nil
}

var (
	requirementNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)
	exactVersionPattern    = regexp.MustCompile(`^==\s*([A-Za-z0-9][A-Za-z0-9._!+-]*)$`)
)

// parseRequirement reads a PEP 508 requirement. The version is declared only
// for a lone `==` specifier; extras, markers and other specifiers are dropped.
func parseRequirement(requirement string) (Package, bool) {
	requirement = strings.TrimSpace(requirement)
	if i := strings.Index(requirement, ";"); i >= 0 {
		requirement = strings.TrimSpace(requirement[:i])
	}
	if strings.Contains(requirement, "@") || strings.Contains(requirement, "://") {
		return Package{}, false
	}

	name := requirementNamePattern.FindString(requirement)
	if name == "" {
		return Package{}, false
	}
	rest := strings.TrimSpace(requirement[len(name):])
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 {
			return Package{}, false
		}
		rest = strings.TrimSpace(rest[end+1:])
	}
	rest = strings.Trim(rest, "()")
	rest = strings.TrimSpace(rest)

	pkg := Package{Name: name}
	if m := exactVersionPattern.FindStringSubmatch(rest); m != nil && !strings.HasSuffix(m[1], ".*") {
		pkg.Version = m[1]
	}

	return pkg, true
}

var rockspecFieldPattern = regexp.MustCompile(`(?m)^\s*(package|version)\s*=\s*"([^"]*)"`)

// parseRockspec declares the rock the rockspec describes: syft catalogs the
// rockspec itself as the only component, under its `package` and `version`.
func parseRockspec(spec []byte) ([]Package, error) {
	var pkg Package
	for _, m := range rockspecFieldPattern.FindAllStringSubmatch(string(spec), -1) {
		switch m[1] {
		case "package":
			pkg.Name = m[2]
		case "version":
			pkg.Version = m[2]
		}
	}
	if pkg.Name == "" {
		return nil, fmt.Errorf("parse rockspec: no package field")
	}

	return []Package{pkg}, nil
}

// sorted orders packages read out of a map, so the edge they produce does not
// change from one build to the next.
func sorted(pkgs []Package) []Package {
	slices.SortFunc(pkgs, func(a, b Package) int { return strings.Compare(a.Name, b.Name) })
	return pkgs
}
