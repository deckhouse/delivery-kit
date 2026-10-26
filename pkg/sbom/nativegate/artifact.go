package nativegate

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type inspector struct {
	policy    *Policy
	image     ImagePolicy
	catalog   *Catalog
	compiled  map[string]Compile
	active    map[string]bool
	languages []string
	tools     []Tool
	archives  map[string][]byte
	fs        *filesystem
}

func readSection(f *elf.File, name string) ([]byte, error) {
	s := f.Section(name)
	if s == nil || s.Size == 0 || s.Size > 16<<20 {
		return nil, fmt.Errorf("missing/oversized mandatory metadata %s", name)
	}
	return s.Data()
}

func (i *inspector) tool(t Tool) error {
	if err := i.policy.checkTool(t); err != nil {
		return err
	}
	if !slices.Contains(i.tools, t) {
		i.tools = append(i.tools, t)
	}
	return nil
}

func (i *inspector) source(s Source) ([]string, error) {
	if i.fs != nil {
		resolved, err := resolvePath(i.fs, s.Path)
		if err != nil {
			return nil, err
		}
		s.Path = resolved
	}
	if !digestPattern.MatchString(s.SHA256) {
		return nil, fmt.Errorf("invalid source hash %s", s.Path)
	}
	if expected, ok := i.image.Sources[s.Path]; ok {
		if expected != s.SHA256 {
			return nil, fmt.Errorf("project source changed %s", s.Path)
		}
		if prohibitedSource(s.Path) {
			return nil, fmt.Errorf("vendored source %s", s.Path)
		}
		if !validComponent(i.image.Project) {
			return nil, fmt.Errorf("incomplete project component")
		}
		i.catalog.Components[i.image.Project.BOMRef] = i.image.Project
		return []string{i.image.Project.BOMRef}, nil
	}
	var owners []string
	for _, r := range i.catalog.Records {
		if (r.Origin == "pm" || r.Origin == "sdk" || r.Origin == "source") && r.Path == s.Path && r.SHA256 == s.SHA256 {
			owners = appendUnique(owners, r.Components...)
		}
	}
	if len(owners) != 1 {
		return nil, fmt.Errorf("unknown/ambiguous source or header %s %s", s.Path, s.SHA256)
	}
	return owners, nil
}

func (i *inspector) input(s Source) ([]string, error) {
	if i.fs != nil {
		resolved, err := resolvePath(i.fs, s.Path)
		if err != nil {
			return nil, err
		}
		s.Path = resolved
	}
	var owners []string
	for _, r := range i.catalog.Records {
		if (r.Origin == "pm" || r.Origin == "sdk") && r.Path == s.Path && r.SHA256 == s.SHA256 {
			owners = appendUnique(owners, r.Components...)
		}
	}
	if len(owners) > 1 {
		return nil, fmt.Errorf("ambiguous package input %s", s.Path)
	}
	if len(owners) == 1 {
		return owners, nil
	}
	r, ok := i.compiled[s.SHA256]
	if !ok {
		return nil, fmt.Errorf("unknown native input %s %s", s.Path, s.SHA256)
	}
	if i.active[s.SHA256] {
		return nil, fmt.Errorf("cyclic compiler provenance %s", s.Path)
	}
	if r.Schema != "dk.compile/v2" || r.SHA256 != s.SHA256 || !digestPattern.MatchString(r.SHA256) || len(r.Sources)+len(r.Inputs) == 0 {
		return nil, fmt.Errorf("invalid compiler provenance %s", s.Path)
	}
	if !slices.Contains([]string{"c", "go", "rust"}, r.Language) {
		return nil, fmt.Errorf("unsupported compiler language %q", r.Language)
	}
	if err := i.tool(r.Tool); err != nil {
		return nil, err
	}
	i.languages = appendUnique(i.languages, r.Language)
	i.active[s.SHA256] = true
	defer delete(i.active, s.SHA256)
	for _, src := range r.Sources {
		refs, err := i.source(src)
		if err != nil {
			return nil, err
		}
		owners = appendUnique(owners, refs...)
	}
	for _, input := range r.Inputs {
		refs, err := i.input(input)
		if err != nil {
			return nil, err
		}
		owners = appendUnique(owners, refs...)
	}
	return owners, nil
}

func (i *inspector) inspect(body []byte) (Record, error) {
	r := Record{SHA256: digest(body), Origin: "build"}
	f, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return r, fmt.Errorf("read ELF artifact: %w", err)
	}
	defer f.Close()
	if f.Machine != elf.EM_X86_64 || f.Class != elf.ELFCLASS64 || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return r, fmt.Errorf("unsupported ELF profile")
	}
	var m Method
	raw, err := readSection(f, ".dk.build")
	if err != nil {
		return r, err
	}
	if err = decode(raw, &m); err != nil {
		return r, fmt.Errorf("decode build profile: %w", err)
	}
	if m.Schema != "dk.build/v2" || len(m.Languages) == 0 || !slices.IsSorted(m.Languages) || len(slices.Compact(slices.Clone(m.Languages))) != len(m.Languages) {
		return r, fmt.Errorf("invalid build profile")
	}
	for _, l := range m.Languages {
		if !slices.Contains([]string{"c", "go", "rust"}, l) {
			return r, fmt.Errorf("unknown build language %s", l)
		}
	}
	if err := i.tool(m.Tool); err != nil {
		return r, err
	}
	needed, err := f.ImportedLibraries()
	if err != nil {
		return r, err
	}
	dynamic := len(needed) > 0 || f.Section(".dynamic") != nil
	mode := "static"
	if dynamic {
		mode = "dynamic"
	}
	r.Profile = strings.Join(m.Languages, "+") + "/" + m.LinkMode + "/" + mode
	if !slices.Contains(i.policy.Profiles, r.Profile) {
		return r, fmt.Errorf("unsupported build profile %s", r.Profile)
	}
	for _, s := range m.Inputs {
		refs, err := i.input(s)
		if err != nil {
			return r, err
		}
		r.Components = appendUnique(r.Components, refs...)
	}
	if m.Native {
		if m.LinkMode != "external" {
			return r, fmt.Errorf("native profile requires external link")
		}
		raw, err = readSection(f, ".dk.link")
		if err != nil {
			return r, err
		}
		var link Link
		if err = decode(raw, &link); err != nil {
			return r, fmt.Errorf("decode native map: %w", err)
		}
		if link.Schema != "dk.link/v2" || link.Mode != mode || len(link.Inputs) == 0 {
			return r, fmt.Errorf("native map contradicts ELF/profile")
		}
		if err = i.tool(link.Linker); err != nil {
			return r, err
		}
		seen := map[string]bool{}
		for _, input := range link.Inputs {
			key := input.Kind + input.Path + input.Member
			if seen[key] || !digestPattern.MatchString(input.SHA256) || input.Path == "" {
				return r, fmt.Errorf("invalid/duplicate native input %s", input.Path)
			}
			seen[key] = true
			if input.Disposition != "included" && input.Disposition != "participated" {
				return r, fmt.Errorf("invalid input disposition")
			}
			source := Source{Path: input.Path, SHA256: input.SHA256}
			switch input.Kind {
			case "archive-member":
				if input.Archive == nil || input.Member == "" || input.Path != input.Archive.Path || input.Disposition != "included" {
					return r, fmt.Errorf("invalid archive member")
				}
				source = *input.Archive
				if err := i.archiveMember(input); err != nil {
					return r, err
				}
			case "archive":
				if input.Disposition != "participated" {
					return r, fmt.Errorf("whole archive cannot imply inclusion")
				}
			case "object":
				if input.Disposition != "included" {
					return r, fmt.Errorf("object must be included")
				}
			case "shared":
				if !dynamic {
					return r, fmt.Errorf("shared input in static ELF")
				}
			default:
				return r, fmt.Errorf("unsupported native input kind %s", input.Kind)
			}
			refs, err := i.input(source)
			if err != nil {
				return r, err
			}
			if input.Disposition == "included" && input.Kind != "shared" {
				r.Components = appendUnique(r.Components, refs...)
			}
		}
	} else if m.LinkMode != "internal" || !slices.Equal(m.Languages, []string{"go"}) || len(m.Inputs) == 0 || dynamic || f.Section(".dk.link") != nil {
		return r, fmt.Errorf("unsupported or contradictory non-native profile")
	}
	if slices.Contains(m.Languages, "go") {
		info, err := buildinfo.Read(bytes.NewReader(body))
		if err != nil {
			return r, fmt.Errorf("missing/corrupt Go buildinfo: %w", err)
		}
		cgo := ""
		for _, s := range info.Settings {
			if s.Key == "CGO_ENABLED" {
				cgo = s.Value
			}
			if s.Key == "-mod" && s.Value == "vendor" {
				return r, fmt.Errorf("vendored Go build")
			}
		}
		if (m.Native && cgo != "1") || (cgo != "0" && cgo != "1") {
			return r, fmt.Errorf("Go buildinfo contradicts profile")
		}
		for _, dep := range info.Deps {
			if dep.Replace != nil {
				dep = dep.Replace
			}
			if dep.Version == "" || dep.Sum == "" {
				return r, fmt.Errorf("Go module lacks version/checksum %s", dep.Path)
			}
			ref := "pkg:golang/" + dep.Path + "@" + dep.Version
			i.catalog.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: dep.Path, Version: dep.Version, PackageURL: ref}
			r.Components = appendUnique(r.Components, ref)
		}
	} else if _, err := buildinfo.Read(bytes.NewReader(body)); err == nil {
		return r, fmt.Errorf("Go binary missing Go profile")
	}
	if slices.Contains(m.Languages, "rust") {
		refs, err := i.rust(f)
		if err != nil {
			return r, err
		}
		r.Components = appendUnique(r.Components, refs...)
	} else if f.Section(".dep-v0") != nil {
		return r, fmt.Errorf("Rust metadata contradicts profile")
	}
	sort.Strings(i.languages)
	if !slices.Equal(i.languages, m.Languages) {
		return r, fmt.Errorf("compiler languages %v contradict build profile %v", i.languages, m.Languages)
	}
	if len(r.Components) == 0 {
		return r, fmt.Errorf("empty artifact composition")
	}
	sort.Strings(r.Components)
	r.Tools = i.tools
	return r, nil
}

func (i *inspector) rust(f *elf.File) ([]string, error) {
	raw, err := readSection(f, ".dep-v0")
	if err != nil {
		return nil, err
	}
	reader, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode Rust metadata: %w", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return nil, fmt.Errorf("invalid Rust metadata size")
	}
	var data struct {
		Packages []struct {
			Name         string `json:"name"`
			Version      string `json:"version"`
			Source       string `json:"source"`
			Kind         string `json:"kind"`
			Root         bool   `json:"root"`
			Dependencies []int  `json:"dependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("decode Rust packages: %w", err)
	}
	if len(data.Packages) == 0 {
		return nil, fmt.Errorf("empty Rust metadata")
	}
	var refs []string
	roots := 0
	for _, p := range data.Packages {
		if p.Name == "" || p.Version == "" {
			return nil, fmt.Errorf("incomplete Rust crate")
		}
		if p.Root {
			roots++
		}
		for _, dep := range p.Dependencies {
			if dep < 0 || dep >= len(data.Packages) {
				return nil, fmt.Errorf("invalid Rust dependency index")
			}
		}
		if p.Kind == "build" {
			continue
		}
		if p.Kind != "" && p.Kind != "runtime" {
			return nil, fmt.Errorf("unknown Rust dependency kind")
		}
		ref := "pkg:cargo/" + p.Name + "@" + p.Version
		i.catalog.Components[ref] = cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: ref, Name: p.Name, Version: p.Version, PackageURL: ref}
		refs = appendUnique(refs, ref)
	}
	if roots != 1 {
		return nil, fmt.Errorf("Rust metadata must have exactly one root")
	}
	return refs, nil
}
