package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"

	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

type pmFiles struct {
	Version  string            `json:"version"`
	Files    map[string]string `json:"files"`
	Symlinks map[string]string `json:"symlinks"`
}

func emptyCatalog() Catalog {
	return Catalog{Schema: "dk.catalog/v5", Components: map[string]cdx.Component{}}
}

func (c *Catalog) add(other Catalog) error {
	if other.Schema != "dk.catalog/v5" {
		return fmt.Errorf("unsupported inherited catalog %q", other.Schema)
	}
	for ref, comp := range other.Components {
		if !validComponent(comp) || ref != comp.BOMRef {
			return fmt.Errorf("incomplete catalog component %s", ref)
		}
		if old, exists := c.Components[ref]; exists && !reflect.DeepEqual(old, comp) {
			return fmt.Errorf("ambiguous component identity %s", ref)
		}
		c.Components[ref] = comp
	}
	for _, r := range other.Records {
		// An archive states its composition through its members, and one holding
		// no member states that it is made of nothing.
		if !digestPattern.MatchString(r.SHA256) || (len(r.Components) == 0 && r.Archive == nil) || !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("invalid catalog record %s", r.Path)
		}
		for _, ref := range r.Components {
			if _, ok := c.Components[ref]; !ok {
				return fmt.Errorf("missing catalog component %s", ref)
			}
		}
		if r.Origin == "pm" && len(r.Owners) == 0 {
			return fmt.Errorf("%s: no-data: missing package owners", r.Path)
		}
		for _, owner := range r.Owners {
			if !slices.Contains(r.Components, owner) {
				return fmt.Errorf("%s: invalid: package owner absent from components", r.Path)
			}
		}
		if r.Origin == "build" && len(r.Composition) == 0 && r.Archive == nil {
			return fmt.Errorf("%s: no-data: missing inherited embedded composition", r.Path)
		}
		if err := checkArchive(r); err != nil {
			return err
		}
		if r.Composition != nil {
			composition, status, err := parseComposition(r.Composition)
			if err != nil {
				return fmt.Errorf("%s: %s: %w", r.Path, status, err)
			}
			if r.Profile != composition.Profile.ID {
				return fmt.Errorf("%s: invalid: inherited profile disagrees with composition", r.Path)
			}
		}
		c.Records = append(c.Records, r)
	}
	return nil
}

func parseComposition(embedded json.RawMessage) (*shared.BuildRecord, string, error) {
	raw, err := json.Marshal(map[string]json.RawMessage{"sbom": embedded})
	if err != nil {
		return nil, "invalid", fmt.Errorf("encode composition: %w", err)
	}

	return shared.ParseBuildRecord(raw)
}

// checkArchive applies to an inherited archive record what reading the file
// itself establishes: every member named, its bytes identified, and its own
// record standing behind the components the archive is credited with. A record
// stating both an archive and a composition of its own claims something no ar
// carries, and is refused rather than read either way.
func checkArchive(r Record) error {
	if r.Archive == nil {
		return nil
	}
	if r.Composition != nil {
		return fmt.Errorf("%s: invalid: an archive carries no build record of its own", r.Path)
	}
	indexes := map[int]bool{}
	for _, member := range r.Archive.Members {
		if member.Name == "" || member.Index < 0 || indexes[member.Index] {
			return fmt.Errorf("%s: invalid: archive member %q takes no distinct ordinal", r.Path, member.Name)
		}
		indexes[member.Index] = true
		if !digestPattern.MatchString(member.SHA256) || len(member.Components) == 0 {
			return fmt.Errorf("%s: invalid: archive member %q states no identified content", r.Path, member.Name)
		}
		if len(member.Composition) == 0 {
			return fmt.Errorf("%s: no-data: missing inherited composition of archive member %q", r.Path, member.Name)
		}
		composition, status, err := parseComposition(member.Composition)
		if err != nil {
			return fmt.Errorf("%s: %s: archive member %q: %w", r.Path, status, member.Name, err)
		}
		if member.Profile != composition.Profile.ID {
			return fmt.Errorf("%s: invalid: inherited profile of archive member %q disagrees with its composition", r.Path, member.Name)
		}
		for _, ref := range member.Components {
			if !slices.Contains(r.Components, ref) {
				return fmt.Errorf("%s: invalid: archive member %q holds component %s the archive is not credited with", r.Path, member.Name, ref)
			}
		}
	}

	return nil
}

// ReadCatalog reads the catalogs the given documents carry, applying every check a build
// applies to a catalog it is handed: a component held under a ref other than its own is
// refused, as is a record naming a component the catalog does not hold. A document whose
// catalog does not load here is a document no consumer of it can resolve.
func ReadCatalog(boms []*cdx.BOM) (Catalog, error) {
	c := emptyCatalog()
	for _, bom := range boms {
		if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil {
			continue
		}
		for _, prop := range *bom.Metadata.Properties {
			if prop.Name != CatalogProperty {
				if strings.HasPrefix(prop.Name, "dk:catalog/") {
					return c, fmt.Errorf("unsupported inherited catalog property %s", prop.Name)
				}
				continue
			}
			var other Catalog
			if err := decode([]byte(prop.Value), &other); err != nil {
				return c, fmt.Errorf("decode inherited catalog: %w", err)
			}
			if err := c.add(other); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

func (c *Catalog) addPM(ctx context.Context, bodies map[string][]byte) error {
	index, hasIndex := bodies["/var/lib/pm/index.json"]
	files, hasFiles := bodies["/var/lib/pm/files.json"]
	if !hasIndex && !hasFiles {
		return nil
	}
	if !hasIndex || !hasFiles {
		return fmt.Errorf("incomplete pm source inventory")
	}
	version := strings.TrimSpace(string(bodies["/var/lib/pm/container-factory-version"]))
	if version == "" {
		return fmt.Errorf("missing pm container-factory version")
	}
	c.pmSnapshot = digest(append(append(append([]byte{}, index...), files...), []byte(version)...))
	pkgs, err := ospm.ParsePmInstalledJSON(index)
	if err != nil {
		return err
	}
	var manifests map[string]pmFiles
	if err := decode(files, &manifests); err != nil {
		return fmt.Errorf("decode original pm files: %w", err)
	}
	bom := ospm.ConvertToCycloneDX(ctx, pkgs, version)
	if bom == nil {
		return fmt.Errorf("empty pm inventory")
	}
	byName := map[string]string{}
	for _, comp := range *bom.Components {
		c.Components[comp.BOMRef] = comp
		byName[comp.Name] = comp.BOMRef
	}
	for name, pkg := range pkgs {
		manifest, ok := manifests[name]
		if !ok || manifest.Version != pkg.Version {
			return fmt.Errorf("pm version/files mismatch: %s", name)
		}
		if !digestPattern.MatchString(pkg.Digest) || pkg.Name != name || !validComponent(c.Components[byName[name]]) {
			return fmt.Errorf("incomplete pm identity: %s", name)
		}
		for path, hash := range manifest.Files {
			if !strings.HasPrefix(hash, "sha256:") {
				hash = "sha256:" + hash
			}
			if !digestPattern.MatchString(hash) {
				return fmt.Errorf("invalid original pm hash: %s", path)
			}
			c.Records = append(c.Records, Record{Path: path, SHA256: hash, Components: []string{byName[name]}, Origin: "pm", Namespace: c.pmSnapshot, Owners: []string{byName[name]}})
		}
	}
	for name := range manifests {
		if _, ok := pkgs[name]; !ok {
			return fmt.Errorf("pm files without installed package %s", name)
		}
	}
	return nil
}

func (c *Catalog) attach(bom *cdx.BOM) error {
	sort.Slice(c.Records, func(i, j int) bool {
		return c.Records[i].Path+c.Records[i].SHA256 < c.Records[j].Path+c.Records[j].SHA256
	})
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	props := []cdx.Property{}
	if bom.Metadata.Properties != nil {
		for _, p := range *bom.Metadata.Properties {
			if p.Name != CatalogProperty {
				props = append(props, p)
			}
		}
	}
	props = append(props, cdx.Property{Name: CatalogProperty, Value: string(data)})
	bom.Metadata.Properties = &props
	return nil
}

func (c *Catalog) coalescePM() error {
	if c.pmSnapshot == "" {
		return nil
	}
	grouped := map[string]Record{}
	records := []Record{}
	for _, r := range c.Records {
		if r.Origin != "pm" {
			records = append(records, r)
			continue
		}
		if r.Namespace != c.pmSnapshot {
			return fmt.Errorf("cannot coalesce historical pm attribution")
		}
		old, ok := grouped[r.Path]
		if !ok {
			grouped[r.Path] = r
			continue
		}
		if old.SHA256 != r.SHA256 {
			return fmt.Errorf("conflicting active pm content %s", r.Path)
		}
		old.Components = appendUnique(old.Components, r.Components...)
		old.Owners = appendUnique(old.Owners, r.Owners...)
		sort.Strings(old.Owners)
		sort.Strings(old.Components)
		grouped[r.Path] = old
	}
	for _, r := range grouped {
		records = append(records, r)
	}
	c.Records = records
	return nil
}
