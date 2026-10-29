package nativegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

type inspector struct {
	policy  *Policy
	catalog *Catalog
}

func (i *inspector) inspect(body []byte) (Record, error) {
	record := Record{SHA256: digest(body), Origin: "build"}
	composition, status, err := shared.ReadELFBuildRecord(bytes.NewReader(body))
	if err != nil {
		return record, fmt.Errorf("%s: %w", status, err)
	}
	if composition.Artifact != "elf" {
		return record, fmt.Errorf("unsupported: expected executable or shared ELF, got %s", composition.Artifact)
	}
	record.Profile = composition.Profile.ID
	if composition.Profile.Platform != "linux/amd64" || !slices.Contains([]string{"c-static", "c-dynamic", "go"}, record.Profile) {
		return record, fmt.Errorf("unsupported: embedded profile %s on %s has no DK dependency agreement check", record.Profile, composition.Profile.Platform)
	}
	if !slices.Contains(i.policy.Profiles, record.Profile) {
		return record, fmt.Errorf("unsupported: build profile %s", record.Profile)
	}
	for _, tool := range composition.Tools {
		identity := Tool{Name: tool.Name, Version: tool.Version, SHA256: tool.SHA256}
		if err := i.policy.checkTool(identity); err != nil {
			return record, err
		}
		record.Tools = append(record.Tools, identity)
	}
	for _, component := range composition.IncludedComponents() {
		converted, err := embeddedComponent(component)
		if err != nil {
			return record, err
		}
		if previous, ok := i.catalog.Components[converted.BOMRef]; ok && !reflect.DeepEqual(previous, converted) {
			return record, fmt.Errorf("invalid: conflicting component identity %s", converted.BOMRef)
		}
		i.catalog.Components[converted.BOMRef] = converted
		record.Components = appendUnique(record.Components, converted.BOMRef)
	}
	sort.Strings(record.Components)
	raw, err := json.Marshal(composition)
	if err != nil {
		return record, fmt.Errorf("encode embedded composition: %w", err)
	}
	record.Composition = raw
	return record, nil
}

func embeddedComponent(component shared.BuildComponent) (cdx.Component, error) {
	identity, err := json.Marshal([]string{component.Source.Kind, component.Source.Locator, component.Version, component.Source.Checksum})
	if err != nil {
		return cdx.Component{}, fmt.Errorf("encode component identity: %w", err)
	}
	source, err := json.Marshal(component.Source)
	if err != nil {
		return cdx.Component{}, fmt.Errorf("encode component source: %w", err)
	}
	qualifiers := packageurl.Qualifiers{{Key: "source_kind", Value: component.Source.Kind}, {Key: "source_locator", Value: component.Source.Locator}}
	if component.Source.Checksum != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "source_checksum", Value: component.Source.Checksum})
	}
	purl := packageurl.NewPackageURL("generic", "", component.Name, component.Version, qualifiers, "").ToString()
	return cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: "urn:dk:component:" + digest(identity), Name: component.Name, Version: component.Version, PackageURL: purl, Properties: &[]cdx.Property{{Name: "dk:source", Value: string(source)}}}, nil
}
