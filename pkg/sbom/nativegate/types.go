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

const catalogProperty = "dk:catalog/v2"

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type Source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Compile struct {
	Schema   string   `json:"schema"`
	SHA256   string   `json:"sha256"`
	Tool     Tool     `json:"tool"`
	Language string   `json:"language"`
	Sources  []Source `json:"sources"`
	Inputs   []Source `json:"inputs"`
}
type Method struct {
	Schema    string   `json:"schema"`
	Languages []string `json:"languages"`
	Native    bool     `json:"native"`
	LinkMode  string   `json:"linkMode"`
	Tool      Tool     `json:"tool"`
	Inputs    []Source `json:"inputs"`
}
type LinkInput struct {
	Path        string  `json:"path"`
	SHA256      string  `json:"sha256"`
	Kind        string  `json:"kind"`
	Disposition string  `json:"disposition"`
	Archive     *Source `json:"archive,omitempty"`
	Member      string  `json:"member,omitempty"`
}
type Link struct {
	Schema string      `json:"schema"`
	Linker Tool        `json:"linker"`
	Mode   string      `json:"mode"`
	Inputs []LinkInput `json:"inputs"`
}
type ImagePolicy struct {
	RuntimeLoads []string          `json:"runtimeLoads"`
	Role         string            `json:"role"`
	Outputs      []string          `json:"outputs"`
	Project      cdx.Component     `json:"project"`
	Sources      map[string]string `json:"sources"`
	MetaDir      string            `json:"metaDir"`
}
type Policy struct {
	PMOverlap     string                 `json:"pmOverlap,omitempty"`
	Distributions []Distribution         `json:"distributions"`
	Schema        string                 `json:"schema"`
	Tools         []Tool                 `json:"tools"`
	Profiles      []string               `json:"profiles"`
	Images        map[string]ImagePolicy `json:"images"`
}
type Record struct {
	PMOverlap  string   `json:"pmOverlap,omitempty"`
	Namespace  string   `json:"namespace,omitempty"`
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	Components []string `json:"components"`
	Origin     string   `json:"origin"`
	Profile    string   `json:"profile,omitempty"`
	Tools      []Tool   `json:"tools,omitempty"`
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

func (p *Policy) checkTool(t Tool) error {
	if t.Name == "" || t.Version == "" || !digestPattern.MatchString(t.SHA256) {
		return fmt.Errorf("incomplete tool identity")
	}
	for _, known := range p.Tools {
		if known == t {
			return nil
		}
	}
	return fmt.Errorf("unregistered tool %s %s %s", t.Name, t.Version, t.SHA256)
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
	return c.Name != "" && c.Version != "" && c.PackageURL != "" && c.BOMRef == c.PackageURL
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

func prohibitedSource(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "vendor" || part == "third_party" || part == "third-party" {
			return true
		}
	}
	return false
}
