package nativegate

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

type goModules struct {
	Schema  string `json:"schema"`
	GoSum   string `json:"goSum"`
	Modules []struct {
		Path    string `json:"path"`
		Version string `json:"version"`
		Dir     string `json:"dir"`
		Zip     string `json:"zip"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
		Sum     string `json:"sum"`
		Source  string `json:"source"`
	} `json:"modules"`
}

func (c *Catalog) addGoModules(ip ImagePolicy, bodies map[string][]byte) error {
	raw, ok := bodies[strings.TrimRight(ip.MetaDir, "/")+"/go-modules.json"]
	if !ok {
		return nil
	}
	var inv goModules
	if err := decode(raw, &inv); err != nil {
		return fmt.Errorf("decode Go module inventory: %w", err)
	}
	if inv.Schema != "dk.go-modules/v1" {
		return fmt.Errorf("unsupported Go module inventory")
	}
	sums, ok := bodies[inv.GoSum]
	if !ok || digest(sums) != c.sourceHash(ip, inv.GoSum) {
		return fmt.Errorf("Go module inventory requires original Git go.sum")
	}
	expected := map[string]string{}
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			expected[fields[0]+"@"+fields[1]] = fields[2]
		}
	}
	for _, m := range inv.Modules {
		if err := module.Check(m.Path, m.Version); err != nil {
			return fmt.Errorf("invalid Go module identity: %w", err)
		}
		escaped, err := module.EscapePath(m.Path)
		if err != nil {
			return err
		}
		version, err := module.EscapeVersion(m.Version)
		if err != nil {
			return err
		}
		if m.Source != "registry" || m.URL != "https://proxy.golang.org/"+escaped+"/@v/"+version+".zip" || !strings.HasSuffix(m.Dir, "/"+escaped+"@"+version) {
			return fmt.Errorf("unsupported Go module source %s", m.Path)
		}
		if m.Sum != expected[m.Path+"@"+m.Version] || !strings.HasPrefix(m.Sum, "h1:") {
			return fmt.Errorf("Go module sum/version disagrees with Git go.sum: %s", m.Path)
		}
		if !strings.HasPrefix(m.Zip, strings.TrimRight(ip.MetaDir, "/")+"/") {
			return fmt.Errorf("Go module archive outside evidence directory")
		}
		body, ok := bodies[m.Zip]
		if !ok || digest(body) != m.SHA256 {
			return fmt.Errorf("Go module transport hash mismatch %s", m.Path)
		}
		reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return err
		}
		files := map[string]*zip.File{}
		names := []string{}
		prefix := m.Path + "@" + m.Version + "/"
		for _, file := range reader.File {
			if !strings.HasPrefix(file.Name, prefix) || path.Clean(file.Name) != file.Name || file.FileInfo().IsDir() {
				return fmt.Errorf("noncanonical module archive member %s", file.Name)
			}
			if _, duplicate := files[file.Name]; duplicate {
				return fmt.Errorf("duplicate module archive member")
			}
			files[file.Name] = file
			names = append(names, file.Name)
		}
		checksum, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) { return files[name].Open() })
		if err != nil {
			return err
		}
		if checksum != m.Sum {
			return fmt.Errorf("Go module canonical h1 mismatch %s", m.Path)
		}
		ref := "pkg:golang/" + m.Path + "@" + m.Version
		props := []cdx.Property{{Name: "dk:go:sum", Value: checksum}}
		refs := []cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: m.URL}}
		c.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: m.Path, Version: m.Version, PackageURL: ref, Properties: &props, ExternalReferences: &refs}
		for _, name := range names {
			r, err := files[name].Open()
			if err != nil {
				return err
			}
			body, err := io.ReadAll(io.LimitReader(r, (64<<20)+1))
			closeErr := r.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if len(body) > 64<<20 {
				return fmt.Errorf("module source too large")
			}
			c.Records = append(c.Records, Record{Path: path.Join(m.Dir, strings.TrimPrefix(name, prefix)), SHA256: digest(body), Components: []string{ref}, Origin: "module"})
		}
	}
	return nil
}

func (c *Catalog) verifyCargoDistribution(ip ImagePolicy, inv sourceInventory, bodies map[string][]byte) error {
	for _, comp := range inv.Components {
		if !strings.HasPrefix(comp.PackageURL, "pkg:cargo/") {
			continue
		}
		found := false
		sourceHashes := map[string]string{}
		for _, r := range c.Records {
			if r.Origin == "source" {
				sourceHashes[r.Path] = r.SHA256
			}
		}
		for name, hash := range ip.Sources {
			sourceHashes[name] = hash
		}
		for name, hash := range sourceHashes {
			if path.Base(name) != "Cargo.lock" {
				continue
			}
			body, ok := bodies[name]
			if !ok || digest(body) != hash {
				return fmt.Errorf("Cargo lock differs from Git")
			}
			var lock struct {
				Version int `toml:"version"`
				Package []struct {
					Name     string `toml:"name"`
					Version  string `toml:"version"`
					Source   string `toml:"source"`
					Checksum string `toml:"checksum"`
				} `toml:"package"`
			}
			if _, err := toml.Decode(string(body), &lock); err != nil {
				return err
			}
			if lock.Version != 3 && lock.Version != 4 {
				return fmt.Errorf("unsupported Cargo lock version")
			}
			for _, p := range lock.Package {
				if p.Name != comp.Name || p.Version != comp.Version {
					continue
				}
				if p.Source != "registry+https://github.com/rust-lang/crates.io-index" || "sha256:"+p.Checksum != inv.Distribution.SHA256 || inv.Distribution.URL != "https://static.crates.io/crates/"+p.Name+"/"+p.Name+"-"+p.Version+".crate" {
					return fmt.Errorf("Cargo source/checksum mismatch %s", p.Name)
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("Cargo crate version missing from original lock %s", comp.PackageURL)
		}
	}
	return nil
}

func componentProperty(c cdx.Component, name string) string {
	if c.Properties != nil {
		for _, p := range *c.Properties {
			if p.Name == name {
				return p.Value
			}
		}
	}
	return ""
}

func validateGoDependencies(deps []goDependency, owned []string, c *Catalog) error {
	seen := []string{}
	for _, dep := range deps {
		ref := "pkg:golang/" + dep.Path + "@" + dep.Version
		if dep.Replace || dep.Version == "" || dep.Sum == "" || !slices.Contains(owned, ref) || componentProperty(c.Components[ref], "dk:go:sum") != dep.Sum {
			return fmt.Errorf("Go buildinfo module lacks matching registry owner/version/h1: %s", dep.Path)
		}
		seen = append(seen, ref)
	}
	for _, ref := range owned {
		if strings.HasPrefix(ref, "pkg:golang/") && !slices.Contains(seen, ref) {
			return fmt.Errorf("Go owner absent from buildinfo %s", ref)
		}
	}
	return nil
}

type goDependency struct {
	Path    string
	Version string
	Sum     string
	Replace bool
}

func (c *Catalog) sourceHash(ip ImagePolicy, name string) string {
	if hash, ok := ip.Sources[name]; ok {
		return hash
	}
	for _, r := range c.Records {
		if r.Origin == "source" && r.Path == name {
			return r.SHA256
		}
	}
	return ""
}
