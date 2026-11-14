package nativegate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type (
	Tool        struct{ Name, Version, SHA256 string }
	ImagePolicy struct {
		Role    string
		Outputs []string
	}
)

type Policy struct {
	Profiles []string
	Platform string
}
type ArchiveMember struct {
	Composition           json.RawMessage
	Name, SHA256, Profile string
	Components            []string
	Index                 int
}
type (
	ArchiveEvidence struct{ Members []ArchiveMember }
	Record          struct {
		Archive                       *ArchiveEvidence
		Composition                   json.RawMessage
		Path, SHA256, Origin, Profile string
		Components, Owners            []string
		Tools                         []Tool
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
	Platform          string
	Subject           string
	UserRoots         []string
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
