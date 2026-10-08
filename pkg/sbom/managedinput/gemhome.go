package managedinput

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"

	"github.com/werf/werf/v3/pkg/sbom/cyclonedxutil"
)

const gemDefaultDir = "/usr/lib/ruby/gems"

// GemHomeDir resolves the directory RubyGems installs into inside the image: $BUNDLE_PATH
// when bundler is the installer and the variable is set, else $GEM_HOME. imageEnv is the
// image config environment (KEY=VALUE entries); overlay (the packages directive env) takes
// precedence over it, matching how the install command sees the environment. A relative
// BUNDLE_PATH is resolved against workdir, where the install command runs. When the image
// declares neither variable RubyGems installs under a directory compiled into the
// interpreter, which is /usr/lib/ruby/gems/<abi> for an interpreter built with the /usr
// prefix; the parent of that directory is returned, since the ABI version is not known
// here. A path bundler reads from a .bundle/config file instead of the environment is not
// seen either.
func GemHomeDir(imageEnv []string, overlay map[string]string, workdir string, bundler bool) string {
	vars := envMap(imageEnv)
	for name, value := range overlay {
		vars[name] = value
	}

	if bundlePath := vars["BUNDLE_PATH"]; bundler && bundlePath != "" {
		if path.IsAbs(bundlePath) {
			return path.Clean(bundlePath)
		}
		return path.Join(workdir, bundlePath)
	}

	if gemHome := vars["GEM_HOME"]; gemHome != "" {
		return path.Clean(gemHome)
	}

	return gemDefaultDir
}

// A Gemfile.lock lists every gem of the bundle, with its version in parentheses, under
// the specs: section of each source, indented by exactly four spaces; the deeper-indented
// lines below each are its dependencies, which are listed on their own as well.
var gemLockSpecPattern = regexp.MustCompile(`(?m)^ {4}(\S+) \(`)

// GemLockNames lists the gems a Gemfile.lock pins: the whole bundle, transitive
// dependencies included, which is exactly what `bundle install` puts into the image. A
// native gem is listed once per platform of the lock; it is named once.
func GemLockNames(lock []byte) []string {
	var names []string
	for _, m := range gemLockSpecPattern.FindAllStringSubmatch(string(lock), -1) {
		names = append(names, m[1])
	}
	return lo.Uniq(names)
}

// InstalledGemVersions reads, from the gemspecs kept under root, the version RubyGems
// installed each gem as: the <version>[-<platform>] of the gemspec file name, which for
// a native gem is the platform variant the image actually holds.
func InstalledGemVersions(root string) (map[string]string, error) {
	versions := map[string]string{}
	err := filepath.WalkDir(root, func(entryPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(filepath.Dir(entryPath)) != "specifications" {
			return nil
		}
		if m := gemspecFileName.FindStringSubmatch(d.Name()); m != nil {
			versions[m[1]] = m[2]
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return versions, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list installed gemspecs under %s: %w", root, err)
	}
	return versions, nil
}

// AlignGemVersions gives the components of an installed-gemspec scan the version the
// gem was installed as. An installed gemspec records a native gem's platform apart from
// its version, so syft reports nokogiri@1.16.0 for the file
// nokogiri-1.16.0-x86_64-linux.gemspec, while the lock, and so the lock scan, says
// nokogiri (1.16.0-x86_64-linux); without this the two scans of one directive would not
// meet on the purl and the installed variant would stay without the gemspec's license.
func AlignGemVersions(bom *cdx.BOM, installed map[string]string) {
	cyclonedxutil.PatchComponents(bom,
		func(c *cdx.Component) bool {
			version, ok := installed[c.Name]
			return ok && strings.HasPrefix(version, c.Version+"-")
		},
		func(c *cdx.Component) {
			version := installed[c.Name]
			c.PackageURL = strings.Replace(c.PackageURL, "@"+c.Version, "@"+version, 1)
			c.Version = version
		},
	)
}

// DropUninstalledGemVariants removes from a lock scan the listings of a native gem for
// the platforms the image does not hold. A lock written for several platforms lists
// such a gem once per platform (nokogiri (1.16.0), nokogiri (1.16.0-x86_64-linux)),
// syft reports each listing, and only the one RubyGems installed exists in the image.
// A gem without an installed gemspec (a git: or path: gem, kept under bundler/gems)
// is not touched.
func DropUninstalledGemVariants(bom *cdx.BOM, installed map[string]string) {
	if bom == nil || bom.Components == nil || len(installed) == 0 {
		return
	}
	kept := lo.Filter(*bom.Components, func(c cdx.Component, _ int) bool {
		version, ok := installed[c.Name]
		return !ok || c.Version == version
	})
	if len(kept) == 0 {
		bom.Components = nil
		return
	}
	*bom.Components = kept
}

var (
	gemspecDependencyPattern = regexp.MustCompile(`(?m)^\s*\w+\.add(_runtime|_development)?_dependency[\s(]+['"]([^'"]+)['"]`)
	gemspecNamePattern       = regexp.MustCompile(`(?m)^\s*\w+\.name\s*=\s*['"]([^'"]+)['"]`)
)

// GemspecNames lists the gems a gemspec puts into the image: the gem itself and its
// runtime dependencies. The dependencies of those are not known from the gemspec; the
// gems installed for them keep no license in the SBOM.
func GemspecNames(spec []byte) []string {
	var names []string
	for _, m := range gemspecDependencyPattern.FindAllStringSubmatch(string(spec), -1) {
		if m[1] == "_development" {
			continue
		}
		names = append(names, m[2])
	}
	if m := gemspecNamePattern.FindStringSubmatch(string(spec)); m != nil {
		names = append(names, m[1])
	}
	return lo.Uniq(names)
}

// gemspecFileName matches the <name>-<version>[-<platform>].gemspec RubyGems writes under
// specifications/: the name is everything before the first "-<digit>", since a version
// starts with a digit while a gem name does not after a dash.
var gemspecFileName = regexp.MustCompile(`^(.+?)-([0-9][^/]*)\.gemspec$`)

// PruneGemspecs keeps, under every specifications/ directory below root, only the
// gemspecs of the named gems and drops the rest along with specifications/default/.
// A gem directory shared with the interpreter holds the gemspecs of the gems that ship
// with it, default and bundled alike; those belong to the interpreter package, not to
// the bundle being scanned.
func PruneGemspecs(root string, names []string) error {
	keep := lo.SliceToMap(names, func(name string) (string, struct{}) { return name, struct{}{} })

	err := filepath.WalkDir(root, func(entryPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		inSpecifications := filepath.Base(filepath.Dir(entryPath)) == "specifications"
		if d.IsDir() {
			if inSpecifications && d.Name() == "default" {
				if err := os.RemoveAll(entryPath); err != nil {
					return fmt.Errorf("remove %s: %w", entryPath, err)
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !inSpecifications {
			return nil
		}
		m := gemspecFileName.FindStringSubmatch(d.Name())
		if m != nil {
			if _, ok := keep[m[1]]; ok {
				return nil
			}
		}
		if err := os.Remove(entryPath); err != nil {
			return fmt.Errorf("remove %s: %w", entryPath, err)
		}
		return nil
	})
	// The copy creates directories only for the files it kept: a gem directory without a
	// single gemspec leaves nothing to walk.
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("prune gemspecs under %s: %w", root, err)
	}
	return nil
}
