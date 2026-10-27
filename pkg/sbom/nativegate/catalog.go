package nativegate

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

type pmFiles struct {
	Version  string            `json:"version"`
	Files    map[string]string `json:"files"`
	Symlinks map[string]string `json:"symlinks"`
}

func emptyCatalog() Catalog {
	return Catalog{Schema: "dk.catalog/v2", Components: map[string]cdx.Component{}}
}

func (c *Catalog) add(other Catalog) error {
	if other.Schema != "dk.catalog/v2" {
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
		if !digestPattern.MatchString(r.SHA256) || len(r.Components) == 0 || !strings.HasPrefix(r.Path, "/") {
			return fmt.Errorf("invalid catalog record %s", r.Path)
		}
		for _, ref := range r.Components {
			if _, ok := c.Components[ref]; !ok {
				return fmt.Errorf("missing catalog component %s", ref)
			}
		}
		c.Records = append(c.Records, r)
	}
	return nil
}

func inherited(boms []*cdx.BOM) (Catalog, error) {
	c := emptyCatalog()
	for _, bom := range boms {
		if bom == nil || bom.Metadata == nil || bom.Metadata.Properties == nil {
			continue
		}
		for _, prop := range *bom.Metadata.Properties {
			if prop.Name != catalogProperty {
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
			c.Records = append(c.Records, Record{Path: path, SHA256: hash, Components: []string{byName[name]}, Origin: "pm", Namespace: c.pmSnapshot})
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
			if p.Name != catalogProperty {
				props = append(props, p)
			}
		}
	}
	props = append(props, cdx.Property{Name: catalogProperty, Value: string(data)})
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
		sort.Strings(old.Components)
		grouped[r.Path] = old
	}
	for _, r := range grouped {
		records = append(records, r)
	}
	c.Records = records
	return nil
}

func (c *Catalog) attribution(s Source, origins []string) ([]string, error) {
	var selected *Record
	for _, r := range c.Records {
		if !slices.Contains(origins, r.Origin) || r.Path != s.Path || r.SHA256 != s.SHA256 {
			continue
		}
		if len(r.Components) > 1 && (r.Origin != "pm" || r.Namespace == "") {
			return nil, fmt.Errorf("invalid attribution group %s", s.Path)
		}
		if selected != nil {
			if selected.Namespace != r.Namespace || selected.Origin != r.Origin || !slices.Equal(selected.Components, r.Components) {
				return nil, fmt.Errorf("ambiguous source attribution %s", s.Path)
			}
		} else {
			copy := r
			selected = &copy
		}
	}
	if selected == nil {
		return nil, nil
	}
	return slices.Clone(selected.Components), nil
}
