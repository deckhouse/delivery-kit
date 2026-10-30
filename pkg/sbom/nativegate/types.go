package nativegate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CatalogProperty is the metadata property a document carries its catalog in.
const CatalogProperty = "dk:catalog/v4"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type ImagePolicy struct {
	Role    string   `json:"role"`
	Outputs []string `json:"outputs"`
}
type Policy struct {
	producerTools bool
	PMOverlap     string                 `json:"pmOverlap,omitempty"`
	Schema        string                 `json:"schema"`
	Tools         []Tool                 `json:"tools"`
	Profiles      []string               `json:"profiles"`
	Images        map[string]ImagePolicy `json:"images"`
}
type Record struct {
	Owners      []string        `json:"owners,omitempty"`
	Composition json.RawMessage `json:"composition,omitempty"`
	PMOverlap   string          `json:"pmOverlap,omitempty"`
	Namespace   string          `json:"namespace,omitempty"`
	Path        string          `json:"path"`
	SHA256      string          `json:"sha256"`
	Components  []string        `json:"components"`
	Origin      string          `json:"origin"`
	Profile     string          `json:"profile,omitempty"`
	Tools       []Tool          `json:"tools,omitempty"`
}
type Catalog struct {
	pmSnapshot string
	Schema     string                   `json:"schema"`
	Records    []Record                 `json:"records"`
	Components map[string]cdx.Component `json:"components"`
}

func digest(body []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(body)) }
func decode(body []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func Load(ctx context.Context) (*Policy, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	path := os.Getenv("WERF_DK_NATIVE_POLICY")
	if path == "" {
		return nil, "", nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read native policy: %w", err)
	}
	var p Policy
	if err := decode(body, &p); err != nil {
		return nil, "", fmt.Errorf("parse native policy: %w", err)
	}
	if p.Schema != "dk.policy/v2" || len(p.Images) == 0 {
		return nil, "", fmt.Errorf("unsupported native policy %q", p.Schema)
	}
	return &p, digest(body), nil
}

// NewDefaultPolicy applies the supported consumer checks to every file in the image.
func NewDefaultPolicy(_ context.Context, imageName string) *Policy {
	return &Policy{producerTools: true, Schema: "dk.policy/v2", Profiles: []string{"c-static", "c-dynamic", "go", "go-cgo-dynamic", "go-macho", "go-pe"}, Images: map[string]ImagePolicy{imageName: {Role: "final"}}}
}

func (p *Policy) checkTool(t Tool) error {
	if t.Name == "" || t.Version == "" || !digestPattern.MatchString(t.SHA256) {
		return fmt.Errorf("incomplete tool identity")
	}
	if p.producerTools {
		return nil
	}
	for _, known := range p.Tools {
		if known == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported: unregistered tool %s %s %s", t.Name, t.Version, t.SHA256)
}

func validComponent(c cdx.Component) bool {
	_, query, _ := strings.Cut(c.PackageURL, "?")
	query, _, _ = strings.Cut(query, "#")
	for _, qualifier := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(qualifier, "=")
		if key == "containerfactoryversion" && strings.TrimSpace(value) == "" {
			return false
		}
	}
	return c.Name != "" && c.Version != "" && c.PackageURL != "" && c.BOMRef != ""
}

func appendUnique(list []string, entries ...string) []string {
	for _, s := range entries {
		found := false
		for _, v := range list {
			if v == s {
				found = true
				break
			}
		}
		if !found {
			list = append(list, s)
		}
	}
	return list
}
