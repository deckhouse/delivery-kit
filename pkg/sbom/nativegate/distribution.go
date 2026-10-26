package nativegate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/ulikunitz/xz"
)

type Distribution struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type sourceInventory struct {
	Schema       string          `json:"schema"`
	Distribution Distribution    `json:"distribution"`
	Components   []cdx.Component `json:"components"`
	Files        []struct {
		Path        string `json:"path"`
		SHA256      string `json:"sha256"`
		Component   string `json:"component"`
		ArchivePath string `json:"archivePath"`
	} `json:"files"`
}

func (c *Catalog) addDistributions(p *Policy, ip ImagePolicy, bodies map[string][]byte) error {
	for name, body := range bodies {
		if !strings.HasPrefix(name, strings.TrimRight(ip.MetaDir, "/")+"/") || (!strings.HasSuffix(name, "/sources.json") && !strings.HasSuffix(name, ".sources.json") && !(strings.Contains(name, "/sources/") && strings.HasSuffix(name, ".json"))) {
			continue
		}
		var inv sourceInventory
		if err := decode(body, &inv); err != nil {
			return fmt.Errorf("decode SDK inventory: %w", err)
		}
		if inv.Schema != "dk.sources/v2" || !digestPattern.MatchString(inv.Distribution.SHA256) || !slices.Contains(p.Distributions, inv.Distribution) {
			return fmt.Errorf("unknown SDK distribution %s", inv.Distribution.URL)
		}
		prefix := strings.TrimRight(ip.MetaDir, "/") + "/distributions/" + strings.TrimPrefix(inv.Distribution.SHA256, "sha256:")
		var stream io.Reader
		if raw, ok := bodies[prefix+".tar.gz"]; ok {
			if digest(raw) != inv.Distribution.SHA256 {
				return fmt.Errorf("SDK distribution hash mismatch")
			}
			r, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				return err
			}
			defer r.Close()
			stream = r
		} else if raw, ok := bodies[prefix+".tar.xz"]; ok {
			if digest(raw) != inv.Distribution.SHA256 {
				return fmt.Errorf("SDK distribution hash mismatch")
			}
			r, err := xz.NewReader(bytes.NewReader(raw))
			if err != nil {
				return err
			}
			stream = r
		} else {
			return fmt.Errorf("missing original SDK distribution")
		}
		wanted := map[string]bool{}
		for _, file := range inv.Files {
			wanted[file.ArchivePath] = true
		}
		hashes := map[string]string{}
		tr := tar.NewReader(stream)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if !wanted[h.Name] {
				continue
			}
			if h.Typeflag != tar.TypeReg {
				return fmt.Errorf("SDK member is not regular %s", h.Name)
			}
			if _, exists := hashes[h.Name]; exists {
				return fmt.Errorf("duplicate SDK member %s", h.Name)
			}
			sum := sha256.New()
			if _, err := io.Copy(sum, tr); err != nil {
				return err
			}
			hashes[h.Name] = fmt.Sprintf("sha256:%x", sum.Sum(nil))
		}
		for _, comp := range inv.Components {
			if !validComponent(comp) {
				return fmt.Errorf("invalid SDK component")
			}
			c.Components[comp.BOMRef] = comp
		}
		for _, file := range inv.Files {
			if !digestPattern.MatchString(file.SHA256) || file.SHA256 != hashes[file.ArchivePath] || !strings.HasPrefix(file.Path, "/") {
				return fmt.Errorf("SDK source/member mismatch %s", file.Path)
			}
			if _, ok := c.Components[file.Component]; !ok {
				return fmt.Errorf("unknown SDK file component")
			}
			c.Records = append(c.Records, Record{Path: file.Path, SHA256: file.SHA256, Components: []string{file.Component}, Origin: "sdk"})
		}
	}
	return nil
}
