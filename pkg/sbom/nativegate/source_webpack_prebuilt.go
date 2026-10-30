package nativegate

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
)

const materializedWebpackPrebuiltFile = "webpack-prebuilt.json"

var webpackPrebuiltDigestRegexp = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// webpackPrebuiltGitPrefix marks the locator of a dependency fetched as a Git repository
// rather than as a published archive.
const webpackPrebuiltGitPrefix = "git+"

// webpackPrebuiltGitLocatorRegexp spells a Git dependency pinned to a full commit, the
// same shape the originals manifest states its own node components by.
var webpackPrebuiltGitLocatorRegexp = regexp.MustCompile(`^git\+(?:https|ssh)://[^\s#]+#([0-9a-f]{40})$`)

// PrebuiltAsset carries the composition an instrumented rebuild observed for one file,
// keyed by the digest of that file's bytes. The caller has already read it out of a
// pinned source image and checked the proof it came from; what is left is to hold it
// against the installed file this very context was just verified against.
type PrebuiltAsset struct {
	// InstalledPath is where the delivered file stands in the produced stage.
	InstalledPath string
	// SHA256 is the digest the rebuild emitted the file with.
	SHA256 string
	// Components are the identities the rebuild proved the file was built from.
	Components []shared.BuildComponent
	// Inputs are the source units of those components the rebuild selected.
	Inputs []PrebuiltInput
}

// PrebuiltInput is one source unit of a delivered composition, named as the rebuild
// named it: a path in the tree that rebuild ran in, not a path of this build.
type PrebuiltInput struct {
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	Components []string `json:"components"`
}

// webpackPrebuilt maps the digest of a file to the composition of the build that emitted
// it. It is private to this writer and the Node collector that reads it beside the
// context: a copied asset whose verified source bytes carry one of these digests is the
// very file that composition was proven for.
type webpackPrebuilt struct {
	Version int                    `json:"version"`
	Entries []webpackPrebuiltEntry `json:"entries"`
}

type webpackPrebuiltEntry struct {
	SHA256     string                  `json:"sha256"`
	Components []shared.BuildComponent `json:"components"`
	Inputs     []PrebuiltInput         `json:"inputs"`
}

// webpackPrebuiltManifest states each delivered composition under the digest of the file
// it belongs to.
//
// When the installed file is an import this context verified, that digest must be the one
// the originals manifest just proved it against: the published distribution must be the
// very thing the rebuild observed, or nothing is written for it. A file installed by the
// project's own package manager is no import of this context and has no digest here; the
// equality is then the collector's to establish, which it does by looking the delivery up
// under the digest of bytes it has just bound to that package's own verified original.
// Either way the bytes decide; only the side that holds them differs.
func webpackPrebuiltManifest(originals webpackOriginals, assets []PrebuiltAsset) ([]byte, error) {
	installed := make(map[string]string, len(originals.Files))
	for _, file := range originals.Files {
		installed[file.Path] = file.SHA256
	}

	manifest := webpackPrebuilt{Version: 1, Entries: []webpackPrebuiltEntry{}}
	held := make(map[string]webpackPrebuiltEntry, len(assets))
	for _, asset := range assets {
		if !webpackPrebuiltDigestRegexp.MatchString(asset.SHA256) {
			return nil, fmt.Errorf("invalid: %s is delivered under no sha256 digest", asset.InstalledPath)
		}
		if err := checkPrebuiltComposition(asset); err != nil {
			return nil, err
		}
		if served, known := installed[asset.InstalledPath]; known && served != asset.SHA256 {
			return nil, fmt.Errorf("hash-mismatch: %s serves %s, and the rebuild emitted %s", asset.InstalledPath, served, asset.SHA256)
		}
		entry := webpackPrebuiltEntry{SHA256: asset.SHA256, Components: asset.Components, Inputs: asset.Inputs}
		// One composition per bytes: a second one for the same file is a
		// contradiction, not something to merge.
		if claimed, taken := held[asset.SHA256]; taken {
			if !samePrebuiltEntry(claimed, entry) {
				return nil, fmt.Errorf("invalid: %s is delivered with a second composition", asset.SHA256)
			}
			continue
		}
		held[asset.SHA256] = entry
	}

	for _, digest := range slices.Sorted(maps.Keys(held)) {
		manifest.Entries = append(manifest.Entries, held[digest])
	}

	return json.Marshal(manifest)
}

// checkPrebuiltComposition holds a delivered composition to the rules the originals
// manifest states its own components by: a published archive with a checksum, or a Git
// commit named by the locator it was fetched through. A rebuild could not have written
// either unless this very machinery had resolved it first.
func checkPrebuiltComposition(asset PrebuiltAsset) error {
	if len(asset.Components) == 0 {
		return fmt.Errorf("no-data: %s is delivered with no components", asset.InstalledPath)
	}
	// A composition of components alone states what the file is said to contain
	// without stating a single byte it was built from. It is not a description of
	// anything, and it is exactly what a forged delivery would carry.
	if len(asset.Inputs) == 0 {
		return fmt.Errorf("no-data: %s is delivered with no inputs", asset.InstalledPath)
	}
	known := make(map[string]bool, len(asset.Components))
	for _, component := range asset.Components {
		if component.ID == "" || known[component.ID] {
			return fmt.Errorf("invalid: %s is delivered with an unnamed or repeated component", asset.InstalledPath)
		}
		if component.Name == "" || component.Version == "" {
			return fmt.Errorf("invalid: %s is delivered with component %s carrying no exact name and version", asset.InstalledPath, component.ID)
		}
		switch component.Source.Kind {
		case "pm":
			// The identity of a prepared source image, which the shared schema
			// requires to be stated as the digest of that image.
			if !webpackPrebuiltDigestRegexp.MatchString(component.Source.Checksum) {
				return fmt.Errorf("invalid: %s is delivered with component %s pinning no image digest", asset.InstalledPath, component.ID)
			}
			if component.Source.Locator == "" {
				return fmt.Errorf("invalid: %s is delivered with component %s pinning no archive", asset.InstalledPath, component.ID)
			}
		case "node":
			// A dependency of the rebuild, named by the lockfile entry it was
			// installed from: either a published archive with its integrity, or a
			// Git repository, which must be pinned to the commit its own locator
			// names.
			if strings.HasPrefix(component.Source.Locator, webpackPrebuiltGitPrefix) {
				commit := webpackPrebuiltGitLocatorRegexp.FindStringSubmatch(component.Source.Locator)
				if commit == nil || component.Source.Checksum != "git-commit:sha1:"+commit[1] {
					return fmt.Errorf("invalid: %s is delivered with component %s pinning no Git commit", asset.InstalledPath, component.ID)
				}
				break
			}
			if component.Source.Locator == "" || component.Source.Checksum == "" {
				return fmt.Errorf("invalid: %s is delivered with component %s pinning no archive", asset.InstalledPath, component.ID)
			}
		default:
			return fmt.Errorf("invalid: %s is delivered with component %s of an unverifiable kind", asset.InstalledPath, component.ID)
		}
		known[component.ID] = true
	}
	claimed := make(map[string]bool, len(asset.Components))
	for _, input := range asset.Inputs {
		if input.Path == "" || !webpackPrebuiltDigestRegexp.MatchString(input.SHA256) {
			return fmt.Errorf("invalid: %s is delivered with an unnamed or undigested input", asset.InstalledPath)
		}
		if len(input.Components) == 0 {
			return fmt.Errorf("invalid: %s is delivered with input %s claimed by no component", asset.InstalledPath, input.Path)
		}
		for _, id := range input.Components {
			if !known[id] {
				return fmt.Errorf("invalid: %s is delivered with input %s claimed by the unknown component %s", asset.InstalledPath, input.Path, id)
			}
			claimed[id] = true
		}
	}
	// A component no input is claimed by contributes nothing that can be pointed
	// at, and is a name added to the composition rather than read out of it.
	for _, component := range asset.Components {
		if !claimed[component.ID] {
			return fmt.Errorf("invalid: %s is delivered with component %s no input is claimed by", asset.InstalledPath, component.ID)
		}
	}

	return nil
}

// samePrebuiltEntry compares two accounts of the same bytes without letting the order
// they were written in stand for a difference.
func samePrebuiltEntry(a, b webpackPrebuiltEntry) bool {
	first, err := json.Marshal(canonicalPrebuiltEntry(a))
	if err != nil {
		return false
	}
	second, err := json.Marshal(canonicalPrebuiltEntry(b))
	if err != nil {
		return false
	}

	return string(first) == string(second)
}

func canonicalPrebuiltEntry(entry webpackPrebuiltEntry) webpackPrebuiltEntry {
	components := slices.Clone(entry.Components)
	slices.SortFunc(components, func(a, b shared.BuildComponent) int { return strings.Compare(a.ID, b.ID) })
	inputs := make([]PrebuiltInput, 0, len(entry.Inputs))
	for _, input := range entry.Inputs {
		claims := slices.Clone(input.Components)
		slices.Sort(claims)
		inputs = append(inputs, PrebuiltInput{Path: input.Path, SHA256: input.SHA256, Components: claims})
	}
	slices.SortFunc(inputs, func(a, b PrebuiltInput) int {
		if by := strings.Compare(a.Path, b.Path); by != 0 {
			return by
		}

		return strings.Compare(a.SHA256, b.SHA256)
	})

	return webpackPrebuiltEntry{SHA256: entry.SHA256, Components: components, Inputs: inputs}
}
