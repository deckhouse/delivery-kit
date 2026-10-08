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
// resolution renames it. A go.mod with a directive this werf does not know —
// which the newer toolchain inside the image accepted — is re-read with the lax
// parser, which skips unknown directives but also `replace`, so the declarations
// then name the original paths.
func parseGoMod(spec []byte) ([]Package, error) {
	mod, err := modfile.Parse("go.mod", spec, nil)
	if err != nil {
		mod, err = modfile.ParseLax("go.mod", spec, nil)
	}
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

// parsePackageJSON declares `dependencies`, `devDependencies`,
// `optionalDependencies` and `peerDependencies`: the install command of the
// directive puts them all into the image. Versions in package.json are ranges,
// so none is declared.
func parsePackageJSON(spec []byte) ([]Package, error) {
	var manifest struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
	}
	if err := json.Unmarshal(spec, &manifest); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	var pkgs []Package
	for _, deps := range []map[string]json.RawMessage{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies} {
		for name := range deps {
			pkgs = append(pkgs, Package{Name: name})
		}
	}

	return sortedUnique(pkgs), nil
}

// parseCargoToml declares `[dependencies]`, `[dev-dependencies]`,
// `[build-dependencies]` and the same three tables under every
// `[target.<cfg>]`: `cargo fetch` puts them all into the image. A dependency
// renamed with `package = "..."` is declared under the crate name. Versions in
// Cargo.toml are caret ranges, so none is declared.
func parseCargoToml(spec []byte) ([]Package, error) {
	var manifest struct {
		Dependencies      map[string]toml.Primitive `toml:"dependencies"`
		DevDependencies   map[string]toml.Primitive `toml:"dev-dependencies"`
		BuildDependencies map[string]toml.Primitive `toml:"build-dependencies"`
		Target            map[string]struct {
			Dependencies      map[string]toml.Primitive `toml:"dependencies"`
			DevDependencies   map[string]toml.Primitive `toml:"dev-dependencies"`
			BuildDependencies map[string]toml.Primitive `toml:"build-dependencies"`
		} `toml:"target"`
	}
	md, err := toml.Decode(string(spec), &manifest)
	if err != nil {
		return nil, fmt.Errorf("parse Cargo.toml: %w", err)
	}

	tables := []map[string]toml.Primitive{manifest.Dependencies, manifest.DevDependencies, manifest.BuildDependencies}
	for _, target := range manifest.Target {
		tables = append(tables, target.Dependencies, target.DevDependencies, target.BuildDependencies)
	}

	var pkgs []Package
	for _, table := range tables {
		for name, prim := range table {
			var detailed struct {
				Package string `toml:"package"`
			}
			if err := md.PrimitiveDecode(prim, &detailed); err == nil && detailed.Package != "" {
				name = detailed.Package
			}
			pkgs = append(pkgs, Package{Name: name})
		}
	}

	return sortedUnique(pkgs), nil
}

// parsePyprojectToml declares the PEP 621 requirement strings of
// `[project].dependencies`, `[project.optional-dependencies].*` and
// `[dependency-groups].*`, and the name-to-constraint tables of
// `[tool.poetry.dependencies]`, `[tool.poetry.dev-dependencies]` and
// `[tool.poetry.group.*.dependencies]`, in which `python` constrains the
// interpreter rather than naming a package. The install commands of the
// directives put every group into the image.
func parsePyprojectToml(spec []byte) ([]Package, error) {
	var manifest struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]toml.Primitive `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies    map[string]toml.Primitive `toml:"dependencies"`
				DevDependencies map[string]toml.Primitive `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]toml.Primitive `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	md, err := toml.Decode(string(spec), &manifest)
	if err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	requirements := slices.Clone(manifest.Project.Dependencies)
	for _, extra := range manifest.Project.OptionalDependencies {
		requirements = append(requirements, extra...)
	}
	for _, group := range manifest.DependencyGroups {
		for _, prim := range group {
			// A group entry is either a requirement string or an `{include-group = ...}`
			// table; the latter names another group, which is read on its own.
			var requirement string
			if err := md.PrimitiveDecode(prim, &requirement); err == nil {
				requirements = append(requirements, requirement)
			}
		}
	}

	var pkgs []Package
	for _, requirement := range requirements {
		if pkg, ok := parseRequirement(requirement); ok {
			pkgs = append(pkgs, pkg)
		}
	}

	poetryTables := []map[string]toml.Primitive{manifest.Tool.Poetry.Dependencies, manifest.Tool.Poetry.DevDependencies}
	for _, group := range manifest.Tool.Poetry.Group {
		poetryTables = append(poetryTables, group.Dependencies)
	}
	for _, table := range poetryTables {
		for name := range table {
			if strings.EqualFold(name, "python") {
				continue
			}
			pkgs = append(pkgs, Package{Name: name})
		}
	}

	return sortedUnique(pkgs), nil
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

// A rockspec is a Lua file; its `package` and `version` fields are string
// literals in double quotes, single quotes or long brackets.
var rockspecFieldPattern = regexp.MustCompile(`(?m)^\s*(package|version)\s*=\s*(?:"([^"]*)"|'([^']*)'|\[\[(.*?)\]\])`)

// parseRockspec declares the rock the rockspec describes: syft catalogs the
// rockspec itself as the only component, under its `package` and `version`.
func parseRockspec(spec []byte) ([]Package, error) {
	var pkg Package
	for _, m := range rockspecFieldPattern.FindAllStringSubmatch(string(spec), -1) {
		value := m[2] + m[3] + m[4]
		switch m[1] {
		case "package":
			pkg.Name = value
		case "version":
			pkg.Version = value
		}
	}
	if pkg.Name == "" {
		return nil, fmt.Errorf("parse rockspec: no package field")
	}

	return []Package{pkg}, nil
}

// A Gemfile is a Ruby file; a dependency is a `gem` call whose first argument is the
// name and whose second, when it is a string, is the requirement.
var gemfileEntryPattern = regexp.MustCompile(`(?m)^\s*gem[\s(]+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?`)

// parseGemfile declares every gem the Gemfile asks for, groups included: `bundle
// install` puts them all into the image. Requirements are usually ranges, so a version
// is declared only for an exact one.
func parseGemfile(spec []byte) ([]Package, error) {
	var pkgs []Package
	for _, m := range gemfileEntryPattern.FindAllStringSubmatch(string(spec), -1) {
		pkgs = append(pkgs, Package{Name: m[1], Version: exactGemVersion(m[2])})
	}

	return sortedUnique(pkgs), nil
}

// A gemspec is a Ruby file; a dependency is an `add_dependency` call, or one of its
// runtime and development aliases, with the same argument shape as a Gemfile `gem` call.
var (
	gemspecDependencyPattern = regexp.MustCompile(`(?m)^\s*\w+\.add(_runtime|_development)?_dependency[\s(]+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?`)
	gemspecFieldPattern      = regexp.MustCompile(`(?m)^\s*\w+\.(name|version)\s*=\s*['"]([^'"]+)['"]`)
)

// parseGemspec declares the runtime dependencies of a gemspec and the gem it describes,
// which `gem install` puts into the image along with them. Development dependencies are
// not installed, so they are not declared. A gem naming itself through a constant rather
// than a literal is not declared, and not cataloged either: syft reads the name the same
// way.
func parseGemspec(spec []byte) ([]Package, error) {
	var pkgs []Package
	for _, m := range gemspecDependencyPattern.FindAllStringSubmatch(string(spec), -1) {
		if m[1] == "_development" {
			continue
		}
		pkgs = append(pkgs, Package{Name: m[2], Version: exactGemVersion(m[3])})
	}

	var self Package
	for _, m := range gemspecFieldPattern.FindAllStringSubmatch(string(spec), -1) {
		switch m[1] {
		case "name":
			self.Name = m[2]
		case "version":
			self.Version = m[2]
		}
	}
	if self.Name != "" {
		pkgs = append(pkgs, self)
	}

	return sortedUnique(pkgs), nil
}

var exactGemVersionPattern = regexp.MustCompile(`^=?\s*([0-9][A-Za-z0-9.]*)$`)

// exactGemVersion keeps a RubyGems requirement that pins one version, dropping the
// ranges `~>`, `>=` and the like.
func exactGemVersion(requirement string) string {
	m := exactGemVersionPattern.FindStringSubmatch(strings.TrimSpace(requirement))
	if m == nil {
		return ""
	}

	return m[1]
}

// sortedUnique orders packages read out of maps and drops the repeats one name
// listed in several tables produces, so the edge does not change from one build
// to the next.
func sortedUnique(pkgs []Package) []Package {
	slices.SortFunc(pkgs, func(a, b Package) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return slices.Compact(pkgs)
}
