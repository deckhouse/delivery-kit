package nativegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	shared "fox.flant.com/deckhouse/container-base/pm.git/sbom"
	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

type inspector struct {
	policy  *Policy
	catalog *Catalog
}

// Each accepted container is pinned to the exact artifact, profile and platform
// the record reader reports together. A policy lists the same canonical profile
// IDs, so a target is reachable only when its own ID is allowed.
var acceptedTargets = []struct{ artifact, profile, platform string }{
	{"elf", "c-static", "linux/amd64"},
	{"elf", "c-dynamic", "linux/amd64"},
	{"elf", "go", "linux/amd64"},
	{"elf", "go-cgo-dynamic", "linux/amd64"},
	{"elf", "go", "linux/arm"},
	{"elf", "go", "linux/arm64"},
	{"macho", "go-macho", "darwin/amd64"},
	{"macho", "go-macho", "darwin/arm64"},
	{"pe", "go-pe", "windows/amd64"},
}

// inspect reads the build record of the native container in body. It reports
// whether the file is a native container at all: a file the reader confirms is
// not one carries no record and is left to the caller's ordinary handling.
func (i *inspector) inspect(body []byte) (Record, bool, error) {
	record := Record{SHA256: digest(body), Origin: "build"}
	bin, err := shared.ReadBuildInfo(bytes.NewReader(body))
	if bin == nil {
		if err != nil {
			return record, false, fmt.Errorf("invalid: %w", err)
		}
		// A file carrying a native magic the reader does not select never
		// falls back to ordinary content, whatever binaryLike recognizes.
		if nativeMagic(body) {
			return record, true, fmt.Errorf("unsupported: not a selected native executable or shared object")
		}
		return record, false, nil
	}
	if err != nil {
		return record, true, fmt.Errorf("%s: %w", bin.Status, err)
	}
	if bin.Status != "present" || bin.SBOM == nil {
		return record, true, fmt.Errorf("%s: missing build record", bin.Status)
	}
	composition := bin.SBOM
	record.Profile = composition.Profile.ID
	accepted := false
	for _, target := range acceptedTargets {
		if target.artifact == composition.Artifact && target.profile == record.Profile && target.platform == composition.Profile.Platform {
			accepted = true
			break
		}
	}
	if !accepted {
		return record, true, fmt.Errorf("unsupported: embedded %s profile %s on %s has no DK dependency agreement check", composition.Artifact, record.Profile, composition.Profile.Platform)
	}
	if !slices.Contains(i.policy.Profiles, record.Profile) {
		return record, true, fmt.Errorf("unsupported: build profile %s", record.Profile)
	}
	for _, tool := range composition.Tools {
		identity := Tool{Name: tool.Name, Version: tool.Version, SHA256: tool.SHA256}
		if err := i.policy.checkTool(identity); err != nil {
			return record, true, err
		}
		record.Tools = append(record.Tools, identity)
	}
	for _, component := range composition.IncludedComponents() {
		converted, err := embeddedComponent(component)
		if err != nil {
			return record, true, err
		}
		if previous, ok := i.catalog.Components[converted.BOMRef]; ok && !reflect.DeepEqual(previous, converted) {
			return record, true, fmt.Errorf("invalid: conflicting component identity %s", converted.BOMRef)
		}
		i.catalog.Components[converted.BOMRef] = converted
		record.Components = appendUnique(record.Components, converted.BOMRef)
	}
	sort.Strings(record.Components)
	raw, err := json.Marshal(composition)
	if err != nil {
		return record, true, fmt.Errorf("encode embedded composition: %w", err)
	}
	record.Composition = raw
	return record, true, nil
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
	return cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: "urn:dk:component:" + digest(identity), Name: component.Name, Version: component.Version, PackageURL: embeddedPackageURL(component), Properties: &[]cdx.Property{{Name: "dk:source", Value: string(source)}}}, nil
}

// goSourceKind is the source of a component the producer read out of an original Go module
// ZIP: its name is the module path and its version the module version.
const goSourceKind = "go"

// embeddedPackageURL names the component the way a catalog of its ecosystem knows it. A Go
// module is published under the verified module path and version, so it gets the standard
// purl of that ecosystem and no qualifier: a resolver answers that purl, while the source
// the build read stays in the dk:source property and in the BOMRef, which carry the
// identity this verification establishes.
//
// Every other source is an identity of this build alone — a package of a private registry,
// a declaration of the user's own code — which no catalog publishes. It keeps the generic
// purl spelling that identity out.
func embeddedPackageURL(component shared.BuildComponent) string {
	if component.Source.Kind == goSourceKind {
		namespace, name := "", component.Name
		if cut := strings.LastIndex(name, "/"); cut >= 0 {
			namespace, name = name[:cut], name[cut+1:]
		}

		return packageurl.NewPackageURL(packageurl.TypeGolang, namespace, name, component.Version, nil, "").ToString()
	}

	qualifiers := packageurl.Qualifiers{{Key: "source_kind", Value: component.Source.Kind}, {Key: "source_locator", Value: component.Source.Locator}}
	if component.Source.Checksum != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{Key: "source_checksum", Value: component.Source.Checksum})
	}

	return packageurl.NewPackageURL(packageurl.TypeGeneric, "", component.Name, component.Version, qualifiers, "").ToString()
}
