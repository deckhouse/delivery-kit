package nativegate

import (
	"encoding/json"
	"fmt"

	"fox.flant.com/deckhouse/container-base/pm.git/sbom/sources"

	ospm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

func readSourcePackage(source sources.Source) (ospm.PmPackageInfo, error) {
	data, err := json.Marshal(map[string]json.RawMessage{"source": source.Packet})
	if err != nil {
		return ospm.PmPackageInfo{}, fmt.Errorf("read source Packet: %w", err)
	}
	packages, err := ospm.ParsePmInstalledJSON(data)
	if err != nil {
		return ospm.PmPackageInfo{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(source.Packet, &fields); err != nil {
		return ospm.PmPackageInfo{}, fmt.Errorf("read source Packet fields: %w", err)
	}
	pkg := packages["source"]
	pkg.Arch = nil
	if arch, exists := fields["arch"]; exists {
		if err := json.Unmarshal(arch, &pkg.Arch); err != nil {
			return ospm.PmPackageInfo{}, fmt.Errorf("read source Packet arch: %w", err)
		}
	}
	return pkg, nil
}
