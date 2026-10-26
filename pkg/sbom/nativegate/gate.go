package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type filesystem struct {
	index      *shippedscope.FileIndex
	bodies     map[string][]byte
	executable map[string]bool
}

func readFilesystem(ctx context.Context, img v1.Image, ip ImagePolicy) (*filesystem, error) {
	index, err := shippedscope.IndexImageFiles(ctx, img)
	if err != nil {
		return nil, err
	}
	if index.Incomplete {
		return nil, fmt.Errorf("incomplete image index")
	}
	fs := &filesystem{index: index, bodies: map[string][]byte{}, executable: map[string]bool{}}
	reader := mutate.Extract(img)
	defer reader.Close()
	tr := tar.NewReader(reader)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := "/" + strings.TrimPrefix(h.Name, "/")
		entry, ok := index.Files[name]
		if !ok {
			continue
		}
		if _, exists := fs.bodies[name]; exists {
			continue
		}
		if h.Size > 512<<20 && (ip.Role == "final" || slices.Contains(ip.Outputs, name)) {
			return nil, fmt.Errorf("file exceeds experimental limit %s", name)
		}
		_, ownSource := ip.Sources[name]
		metadata := name == "/var/lib/pm/index.json" || name == "/var/lib/pm/files.json"
		capture := ownSource || ip.Role == "final" || slices.Contains(ip.Outputs, name) || name == "/var/lib/pm/index.json" || name == "/var/lib/pm/files.json" || (ip.MetaDir != "" && strings.HasPrefix(name, strings.TrimRight(ip.MetaDir, "/")+"/"))
		if !capture {
			for _, out := range ip.Outputs {
				if index.Files[out].Digest == entry.Digest {
					capture = true
					break
				}
			}
		}
		if !capture {
			continue
		}
		prefix := make([]byte, min(h.Size, 16))
		if _, err := io.ReadFull(tr, prefix); err != nil {
			return nil, err
		}
		body := prefix
		err = nil
		full := metadata || ip.Role != "final" || bytes.HasPrefix(prefix, []byte("\x7fELF"))
		if full {
			rest, readErr := io.ReadAll(tr)
			err = readErr
			body = append(body, rest...)
		}
		if err != nil {
			return nil, err
		}
		if full && digest(body) != entry.Digest {
			return nil, fmt.Errorf("filesystem/index mismatch %s", name)
		}
		fs.bodies[name] = body
		fs.executable[name] = h.Mode&0o111 != 0
	}
	for name, entry := range index.Files {
		if ip.Role != "final" && !slices.Contains(ip.Outputs, name) {
			continue
		}
		if _, ok := fs.bodies[name]; ok {
			continue
		}
		found := false
		for candidate, body := range fs.bodies {
			if index.Files[candidate].Digest == entry.Digest {
				fs.bodies[name] = body
				fs.executable[name] = fs.executable[candidate]
				found = true
				break
			}
		}
		if !found && (ip.Role == "final" || slices.Contains(ip.Outputs, name)) {
			return nil, fmt.Errorf("unreadable surviving file %s", name)
		}
	}
	return fs, nil
}

func binaryLike(body []byte, executable bool, name string) bool {
	return executable || bytes.HasPrefix(body, []byte("\x7fELF")) || bytes.HasPrefix(body, []byte("MZ")) || bytes.HasPrefix(body, []byte("\x00asm")) || bytes.HasPrefix(body, []byte("!<arch>")) || bytes.HasPrefix(body, []byte("!<thin>")) || strings.HasSuffix(name, ".o") || strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".a")
}

func matching(c Catalog, name, hash string) (*Record, error) {
	var result *Record
	pathSeen := false
	pathMatch := false
	for _, r := range c.Records {
		if r.Path == name {
			pathSeen = true
			if r.SHA256 == hash {
				pathMatch = true
			}
		}
		if r.SHA256 != hash {
			continue
		}
		if result == nil {
			copy := r
			result = &copy
			continue
		}
		a, b := slices.Clone(result.Components), slices.Clone(r.Components)
		sort.Strings(a)
		sort.Strings(b)
		if !slices.Equal(a, b) || result.Origin != r.Origin {
			return nil, fmt.Errorf("ambiguous content ownership %s", name)
		}
	}
	if pathSeen && !pathMatch {
		return nil, fmt.Errorf("known file content changed %s", name)
	}
	return result, nil
}

func Apply(ctx context.Context, p *Policy, name string, img v1.Image, inputs []*cdx.BOM, target *cdx.BOM) error {
	ip, ok := p.Images[name]
	if !ok {
		return fmt.Errorf("image %s missing native policy", name)
	}
	if ip.Role != "produce" && ip.Role != "final" {
		return fmt.Errorf("unknown native image role %s", ip.Role)
	}
	fs, err := readFilesystem(ctx, img, ip)
	if err != nil {
		return fmt.Errorf("read final filesystem: %w", err)
	}
	c, err := inherited(inputs)
	if err != nil {
		return err
	}
	local := emptyCatalog()
	if err := local.addPM(ctx, fs.bodies); err != nil {
		return err
	}
	if err := local.addDistributions(p, ip, fs.bodies); err != nil {
		return err
	}
	if err := c.add(local); err != nil {
		return err
	}
	if ip.Role == "produce" {
		for source := range ip.Sources {
			if prohibitedSource(source) || binaryLike(fs.bodies[source], false, source) {
				return fmt.Errorf("prebuilt or vendored project source %s", source)
			}
		}
		records := map[string]Compile{}
		prefix := strings.TrimRight(ip.MetaDir, "/") + "/objects/"
		if ip.MetaDir == "" {
			return fmt.Errorf("missing compiler metadata directory")
		}
		for name, body := range fs.bodies {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			var r Compile
			if err := decode(body, &r); err != nil {
				return fmt.Errorf("decode compiler record %s: %w", name, err)
			}
			if path.Base(name) != strings.TrimPrefix(r.SHA256, "sha256:")+".json" {
				return fmt.Errorf("compiler record filename/hash mismatch")
			}
			records[r.SHA256] = r
		}
		for _, name := range ip.Outputs {
			body, ok := fs.bodies[name]
			if !ok {
				return fmt.Errorf("missing declared output %s", name)
			}
			ins := inspector{policy: p, image: ip, catalog: &local, compiled: records, active: map[string]bool{}, archives: fs.bodies, fs: fs}
			record, err := ins.inspect(body)
			if err != nil {
				return fmt.Errorf("finalize %s: %w", name, err)
			}
			record.Path = name
			c.Records = append(c.Records, record)
		}
		for ref, comp := range local.Components {
			c.Components[ref] = comp
		}
	}
	present := map[string]Record{}
	for name, entry := range fs.index.Files {
		if ip.Role == "produce" && !slices.Contains(ip.Outputs, name) {
			continue
		}
		record, err := matching(c, name, entry.Digest)
		if err != nil {
			return err
		}
		if record == nil {
			if binaryLike(fs.bodies[name], fs.executable[name], name) {
				return fmt.Errorf("unknown binary or unsupported format %s", name)
			}
			continue
		}
		if record.Origin == "build" {
			if !slices.Contains(p.Profiles, record.Profile) {
				return fmt.Errorf("inherited unsupported profile %s", record.Profile)
			}
			for _, t := range record.Tools {
				if err := p.checkTool(t); err != nil {
					return err
				}
			}
		}
		present[name] = *record
	}
	if ip.Role == "final" {
		cfg, err := img.ConfigFile()
		if err != nil {
			return err
		}
		for _, env := range cfg.Config.Env {
			key, value, _ := strings.Cut(env, "=")
			if value != "" && slices.Contains([]string{"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"}, key) {
				return fmt.Errorf("unsupported dynamic loader environment %s", key)
			}
		}
		if err := dynamicClosure(fs, present); err != nil {
			return err
		}
	}
	components := map[string]cdx.Component{}
	deps := []cdx.Dependency{}
	for name, r := range present {
		ref := r.SHA256 + ":" + name
		hashes := []cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: strings.TrimPrefix(r.SHA256, "sha256:")}}
		components[ref] = cdx.Component{Type: cdx.ComponentTypeFile, BOMRef: ref, Name: name, Hashes: &hashes}
		refs := slices.Clone(r.Components)
		sort.Strings(refs)
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: &refs})
		for _, ref := range refs {
			components[ref] = c.Components[ref]
		}
	}
	list := []cdx.Component{}
	for _, comp := range components {
		list = append(list, comp)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].BOMRef < list[j].BOMRef })
	sort.Slice(deps, func(i, j int) bool { return deps[i].Ref < deps[j].Ref })
	target.Components = &list
	target.Dependencies = &deps
	if target.Metadata != nil && target.Metadata.Component != nil {
		refs := []string{}
		for name, r := range present {
			refs = append(refs, r.SHA256+":"+name)
		}
		sort.Strings(refs)
		*target.Dependencies = append(*target.Dependencies, cdx.Dependency{Ref: target.Metadata.Component.BOMRef, Dependencies: &refs})
	}
	for name, r := range present {
		r.Path = name
		c.Records = append(c.Records, r)
	}
	return c.attach(target)
}

func resolvePath(fs *filesystem, name string) (string, error) {
	for n := 0; n < 40; n++ {
		parts := strings.Split(strings.TrimPrefix(path.Clean(name), "/"), "/")
		prefix := "/"
		changed := false
		for pos, part := range parts {
			prefix = path.Join(prefix, part)
			if target, ok := fs.index.Symlinks[prefix]; ok {
				if !strings.HasPrefix(target, "/") {
					target = path.Join(path.Dir(prefix), target)
				}
				name = path.Join(append([]string{target}, parts[pos+1:]...)...)
				changed = true
				break
			}
		}
		if !changed {
			return path.Clean(name), nil
		}
	}
	return "", fmt.Errorf("symlink cycle %s", name)
}

func dynamicClosure(fs *filesystem, present map[string]Record) error {
	edges := map[string][]string{}
	for name := range present {
		body := fs.bodies[name]
		if !bytes.HasPrefix(body, []byte("\x7fELF")) {
			continue
		}
		f, err := elf.NewFile(bytes.NewReader(body))
		if err != nil {
			return err
		}
		if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
			f.Close()
			return fmt.Errorf("unsupported runtime ELF architecture")
		}
		if f.Section(".dynamic") != nil {
			for candidate := range fs.index.Files {
				if candidate == "/etc/ld.so.cache" || candidate == "/etc/ld.so.preload" || strings.Contains(candidate, "/glibc-hwcaps/") {
					f.Close()
					return fmt.Errorf("unsupported dynamic loader feature %s", candidate)
				}
			}
		}
		needed, err := f.ImportedLibraries()
		if err != nil {
			f.Close()
			return err
		}
		for _, prog := range f.Progs {
			if prog.Type == elf.PT_INTERP {
				raw, err := io.ReadAll(prog.Open())
				if err != nil {
					f.Close()
					return err
				}
				needed = append(needed, strings.TrimRight(string(raw), "\x00"))
			}
		}
		dirs := []string{"/lib64", "/lib", "/usr/lib64", "/usr/lib"}
		for _, tag := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
			entries, err := f.DynString(tag)
			if err != nil {
				f.Close()
				return err
			}
			if tag == elf.DT_RPATH && len(entries) > 0 {
				f.Close()
				return fmt.Errorf("DT_RPATH inheritance unsupported; use DT_RUNPATH")
			}
			search := []string{}
			for _, entry := range entries {
				for _, dir := range strings.Split(entry, ":") {
					dir = strings.ReplaceAll(dir, "${ORIGIN}", path.Dir(name))
					dir = strings.ReplaceAll(dir, "$ORIGIN", path.Dir(name))
					if !strings.HasPrefix(dir, "/") || strings.Contains(dir, "$") {
						f.Close()
						return fmt.Errorf("unsupported runtime search path %s", dir)
					}
					search = append(search, dir)
				}
			}
			dirs = append(search, dirs...)
		}
		f.Close()
		for _, soname := range needed {
			candidates := []string{}
			if strings.Contains(soname, "/") {
				if !strings.HasPrefix(soname, "/") {
					return fmt.Errorf("relative DT_NEEDED unsupported %s", soname)
				}
				candidates = append(candidates, soname)
			} else {
				for _, dir := range dirs {
					candidates = append(candidates, path.Join(dir, soname))
				}
			}
			found := false
			for _, candidate := range candidates {
				resolved, err := resolvePath(fs, candidate)
				if err != nil {
					return err
				}
				if _, exists := fs.index.Files[resolved]; !exists {
					continue
				}
				_, known := present[resolved]
				if !known {
					return fmt.Errorf("unknown runtime dependency %s", resolved)
				}
				df, err := elf.NewFile(bytes.NewReader(fs.bodies[resolved]))
				if err != nil {
					return fmt.Errorf("runtime dependency is not ELF %s", resolved)
				}
				names, err := df.DynString(elf.DT_SONAME)
				df.Close()
				if err != nil {
					return err
				}
				if !strings.Contains(soname, "/") && !slices.Contains(names, soname) {
					return fmt.Errorf("runtime SONAME mismatch %s", resolved)
				}
				edges[name] = appendUnique(edges[name], resolved)
				found = true
				break
			}
			if !found {
				return fmt.Errorf("missing runtime dependency %s required by %s", soname, name)
			}
		}
	}
	closeComponents(present, edges)
	return nil
}

func closeComponents(present map[string]Record, edges map[string][]string) {
	for changed := true; changed; {
		changed = false
		for name, children := range edges {
			r := present[name]
			before := len(r.Components)
			for _, child := range children {
				r.Components = appendUnique(r.Components, present[child].Components...)
			}
			if len(r.Components) != before {
				changed = true
			}
			sort.Strings(r.Components)
			present[name] = r
		}
	}
}
