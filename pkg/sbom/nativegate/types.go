package nativegate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"

	osPm "github.com/werf/werf/v3/pkg/sbom/packages/os_pm"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type TrustedPackages map[string]osPm.PmPackageInfo

type (
	Tool struct{ Name, Version, SHA256 string }
)

type Policy struct {
	Profiles []string
	Platform string
}

func strictPolicy(platform string) *Policy {
	return &Policy{Platform: platform, Profiles: []string{"c-object", "c-relocatable", "c-static", "c-dynamic", "go", "go-cgo-static", "go-cgo-dynamic", "go-link-object"}}
}

type ArchiveMember struct {
	Composition           json.RawMessage
	Name, SHA256, Profile string
	Components            []string
	Index                 int
	Subject               string
}
type (
	ArchiveEvidence struct{ Members []ArchiveMember }
	Record          struct {
		Archive                                   *ArchiveEvidence
		Composition                               json.RawMessage
		Subject                                   string
		Path, SourcePath, SHA256, Origin, Profile string
		Components, Owners                        []string
		Tools                                     []Tool
	}
)
type Catalog struct{ Components map[string]cdx.Component }

type Original struct {
	Path       string
	SourcePath string
	SHA256     string
	Component  cdx.Component
	Kind       string
}

type VerifyOptions struct {
	BuildGitSources   [][]GitSource
	Platform          string
	Subject           string
	UserRoots         []string
	ExpectedSymlinks  map[string]string
	Originals         []Original
	TrustedComponents []cdx.Component
}

func digest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }
func appendUnique(list []string, entries ...string) []string {
	for _, entry := range entries {
		if !slices.Contains(list, entry) {
			list = append(list, entry)
		}
	}
	return list
}

func (p *Policy) checkTool(t Tool) error {
	if t.Name == "" || t.Version == "" || !digestPattern.MatchString(t.SHA256) {
		return fmt.Errorf("incomplete tool identity")
	}
	return nil
}
