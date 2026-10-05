package declared

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"
)

// GoModGraphEdges turns the output of `go mod graph` into dependency edges
// between the Go module components of bom.
//
// `go mod graph` prints the unpruned requirement graph: every module version
// any module in the graph ever required, not only the versions the build
// selects. The BOM lists the selected versions only, so an edge is kept when
// its source is a selected version of its module and its target is collapsed
// onto the selected version of its module; an edge whose target module is not
// in the BOM at all is dropped. Edges sourced at the main module are dropped
// too: what the main module requires directly is declared from go.mod, where
// the `// indirect` marker tells direct requirements apart.
func GoModGraphEdges(bom *cdx.BOM, graph []byte) ([]cdx.Dependency, error) {
	selected := make(map[string]string)
	refOf := make(map[string]string)
	walkComponents(bom, func(comp *cdx.Component) {
		if comp.BOMRef == "" || comp.PackageURL == "" {
			return
		}
		purl, err := packageurl.FromString(comp.PackageURL)
		if err != nil || purl.Type != packageurl.TypeGolang {
			return
		}
		module := strings.ToLower(fullName(purl))
		selected[module] = purl.Version
		refOf[module+"@"+purl.Version] = comp.BOMRef
	})

	edges := make(map[string][]string)
	var order []string
	scanner := bufio.NewScanner(bytes.NewReader(graph))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		from, to, found := strings.Cut(line, " ")
		if !found {
			return nil, fmt.Errorf("parse go mod graph line %q", line)
		}

		fromModule, fromVersion, isModule := strings.Cut(from, "@")
		if !isModule {
			continue
		}
		fromModule = strings.ToLower(fromModule)
		if selected[fromModule] != fromVersion {
			continue
		}

		toModule, _, _ := strings.Cut(to, "@")
		toModule = strings.ToLower(toModule)
		toVersion, inBuild := selected[toModule]
		if !inBuild {
			continue
		}

		fromRef := refOf[fromModule+"@"+fromVersion]
		toRef := refOf[toModule+"@"+toVersion]
		if fromRef == toRef {
			continue
		}
		if _, seen := edges[fromRef]; !seen {
			order = append(order, fromRef)
		}
		edges[fromRef] = append(edges[fromRef], toRef)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go mod graph: %w", err)
	}

	deps := make([]cdx.Dependency, 0, len(order))
	for _, ref := range order {
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: lo.ToPtr(lo.Uniq(edges[ref]))})
	}

	return deps, nil
}
