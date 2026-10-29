package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
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
		metadata := name == "/var/lib/pm/index.json" || name == "/var/lib/pm/files.json" || name == "/var/lib/pm/container-factory-version"
		capture := metadata || ip.Role == "final" || slices.Contains(ip.Outputs, name) || name == "/var/lib/pm/index.json" || name == "/var/lib/pm/files.json"
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
		// A script is classified from its whole body, so a shebang is read in full the way
		// an ELF is; the digest check below then ties those bytes to the index.
		full := metadata || ip.Role != "final" || nativeCandidate(prefix) || bytes.HasPrefix(prefix, []byte("#!"))
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

// nativeMagic reports whether prefix starts a container the record reader
// selects by magic alone.
func nativeMagic(prefix []byte) bool {
	for _, magic := range []string{"\x7fELF", "MZ", "\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca", "\xca\xfe\xba\xbf", "\xbf\xba\xfe\xca", "\xfe\xed\xfa\xce", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xcf\xfa\xed\xfe"} {
		if bytes.HasPrefix(prefix, []byte(magic)) {
			return true
		}
	}
	return false
}

// nativeCandidate reports whether a whole body must be captured for the record
// reader to judge it. A bare COFF object has no magic, only the machine id the
// reader classifies on, so that id is enough to read the file in full; the
// reader, not this guess, decides whether the file is native at all.
func nativeCandidate(prefix []byte) bool {
	if nativeMagic(prefix) {
		return true
	}
	if len(prefix) < 2 {
		return false
	}
	// Keep capture candidates aligned with the shared reader's classifyCOFFObject.
	switch binary.LittleEndian.Uint16(prefix) {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_I386, pe.IMAGE_FILE_MACHINE_ARM,
		pe.IMAGE_FILE_MACHINE_ARMNT, pe.IMAGE_FILE_MACHINE_ARM64, pe.IMAGE_FILE_MACHINE_IA64:
		return true
	}
	return false
}

func binaryLike(body []byte, executable bool, name string) bool {
	for _, magic := range []string{"\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca", "\xfe\xed\xfa\xce", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xcf\xfa\xed\xfe", "BC\xc0\xde"} {
		if bytes.HasPrefix(body, []byte(magic)) {
			return true
		}
	}
	return executable || bytes.HasPrefix(body, []byte("\x7fELF")) || bytes.HasPrefix(body, []byte("MZ")) || bytes.HasPrefix(body, []byte("\x00asm")) || bytes.HasPrefix(body, []byte("!<arch>")) || bytes.HasPrefix(body, []byte("!<thin>")) || strings.HasSuffix(name, ".o") || strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".a")
}

func matching(c Catalog, name, hash string) (*Record, error) {
	var result *Record
	pathSeen := false
	pathMatch := false
	for _, r := range c.Records {
		if r.Origin != "pm" && r.Origin != "build" {
			continue
		}
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
		if result.Origin == "pm" && r.Origin == "pm" {
			a, b = slices.Clone(result.Owners), slices.Clone(r.Owners)
		}
		sort.Strings(a)
		sort.Strings(b)
		if !slices.Equal(a, b) || result.Origin != r.Origin || result.Namespace != r.Namespace {
			return nil, fmt.Errorf("ambiguous content ownership %s", name)
		}
	}
	if pathSeen && !pathMatch && result == nil {
		return nil, fmt.Errorf("hash-mismatch: known file content changed %s", name)
	}
	return result, nil
}

func Apply(ctx context.Context, p *Policy, name string, img v1.Image, inputs []*cdx.BOM, target *cdx.BOM) error {
	return apply(ctx, p, name, img, inputs, target, nil)
}

type ApplySourceSnapshotsOptions struct {
	BaseBOM *cdx.BOM
}

// ApplySourceSnapshots verifies the final image using observed, scoped original sources.
func ApplySourceSnapshots(ctx context.Context, p *Policy, name string, img v1.Image, snapshots []SourceSnapshot, target *cdx.BOM, opts ApplySourceSnapshotsOptions) error {
	evidence, err := collectSourceEvidence(ctx, snapshots, opts.BaseBOM)
	if err != nil {
		return err
	}
	if err := apply(ctx, p, name, img, nil, target, evidence); err != nil {
		return err
	}
	return evidence.attach(target)
}

func apply(ctx context.Context, p *Policy, name string, img v1.Image, inputs []*cdx.BOM, target *cdx.BOM, evidence *sourceEvidence) error {
	if p.PMOverlap != "" && p.PMOverlap != "all-active-exact-path-hash" {
		return fmt.Errorf("unsupported pm overlap policy")
	}
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
	if evidence != nil {
		if !maps.Equal(fs.index.Files, evidence.index.Files) || !maps.Equal(fs.index.Symlinks, evidence.index.Symlinks) {
			return fmt.Errorf("invalid: final source snapshot differs from the verified image")
		}
		if err := local.addOriginalSources(ctx, evidence); err != nil {
			return err
		}
	} else if err := local.addPM(ctx, fs.bodies); err != nil {
		return err
	}
	if err := local.resolvePaths(fs); err != nil {
		return err
	}
	if p.PMOverlap != "" {
		if err := local.coalescePM(); err != nil {
			return err
		}
	}
	if err := c.add(local); err != nil {
		return err
	}
	if ip.Role == "produce" {
		for _, name := range ip.Outputs {
			if _, ok := fs.index.Files[name]; !ok {
				return fmt.Errorf("missing declared output %s", name)
			}
		}
	}
	scoped := map[string]Record{}
	if evidence != nil {
		for _, record := range c.Records {
			if _, exists := scoped[record.Path]; exists {
				return fmt.Errorf("invalid: duplicate original record at %s", record.Path)
			}
			scoped[record.Path] = record
		}
	}
	present := map[string]Record{}
	for name, entry := range fs.index.Files {
		if ip.Role == "produce" && !slices.Contains(ip.Outputs, name) {
			continue
		}
		if evidence != nil && binaryLike(fs.bodies[name], fs.executable[name], name) && len(evidence.matches[name]) > 0 {
			if _, err := uniqueOriginalBinding(evidence.matches[name]); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		var record *Record
		if evidence != nil {
			if known, exists := scoped[name]; exists && known.SHA256 == entry.Digest {
				record = &known
			}
		} else {
			var err error
			record, err = matching(c, name, entry.Digest)
			if err != nil {
				return err
			}
		}
		if record != nil && (record.PMOverlap != "" || (record.Origin == "pm" && len(record.Owners) > 1)) && p.PMOverlap != "all-active-exact-path-hash" {
			return fmt.Errorf("pm coownership requires current policy opt-in")
		}
		ins := inspector{policy: p, catalog: &c}
		embedded, native, err := ins.inspect(fs.bodies[name])
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if native {
			if record != nil {
				embedded.Owners = slices.Clone(record.Owners)
				embedded.Components = appendUnique(embedded.Components, record.Owners...)
				embedded.Origin = record.Origin
				embedded.Namespace = record.Namespace
				embedded.PMOverlap = record.PMOverlap
				if record.Origin == "pm" && len(record.Owners) > 1 {
					embedded.PMOverlap = p.PMOverlap
				}
			}
			record = &embedded
		}
		if record != nil && record.Composition != nil && !native {
			return fmt.Errorf("%s: invalid: recorded native composition does not match file", name)
		}
		if !native && binaryLike(fs.bodies[name], false, name) {
			return fmt.Errorf("%s: unsupported: binary format has no embedded composition reader", name)
		}
		if record == nil {
			if binaryLike(fs.bodies[name], fs.executable[name], name) {
				if !interpretedScript(fs.bodies[name], name) {
					return fmt.Errorf("unsupported: unknown binary or unsupported format %s", name)
				}
				// Reading the script as ordinary text must not drop the answer the binary
				// route gave about a path an original source bound before it changed.
				if evidence != nil && evidence.unverified[name] {
					return fmt.Errorf("no-data: content an original source bound at %s changed", name)
				}
			}
			continue
		}
		present[name] = *record
	}
	runtimeEdges := map[string][]string{}
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
		runtimeEdges, err = runtimeDependencies(fs, present)
		if err != nil {
			return err
		}
	}
	if p.PMOverlap != "" {
		if target.Metadata == nil {
			target.Metadata = &cdx.Metadata{}
		}
		if target.Metadata.Properties == nil {
			target.Metadata.Properties = &[]cdx.Property{}
		}
		*target.Metadata.Properties = append(*target.Metadata.Properties, cdx.Property{Name: "dk:pm-overlap", Value: p.PMOverlap})
	}
	return c.writeBOM(present, runtimeEdges, target)
}

func (c *Catalog) writeBOM(present map[string]Record, runtimeEdges map[string][]string, target *cdx.BOM) error {
	components := map[string]cdx.Component{}
	deps := []cdx.Dependency{}
	for name, r := range present {
		ref := r.SHA256 + ":" + name
		hashes := []cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: strings.TrimPrefix(r.SHA256, "sha256:")}}
		components[ref] = cdx.Component{Type: cdx.ComponentTypeFile, BOMRef: ref, Name: name, Hashes: &hashes}
		refs := slices.Clone(r.Components)
		for _, dependency := range runtimeEdges[name] {
			refs = appendUnique(refs, present[dependency].SHA256+":"+dependency)
		}
		sort.Strings(refs)
		deps = append(deps, cdx.Dependency{Ref: ref, Dependencies: &refs})
		for _, ref := range r.Components {
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
	next := emptyCatalog()
	for name, r := range present {
		r.Path = name
		next.Records = append(next.Records, r)
		for _, ref := range r.Components {
			next.Components[ref] = c.Components[ref]
		}
	}
	if target.Metadata == nil {
		target.Metadata = &cdx.Metadata{}
	}
	props := []cdx.Property{}
	if target.Metadata.Properties != nil {
		props = append(props, (*target.Metadata.Properties)...)
	}

	target.Metadata.Properties = &props
	return next.attach(target)
}

func (c *Catalog) resolvePaths(fs *filesystem) error {
	for n := range c.Records {
		resolved, err := resolvePath(fs, c.Records[n].Path)
		if err != nil {
			return err
		}
		c.Records[n].Path = resolved
	}
	return nil
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

func runtimeDependencies(fs *filesystem, present map[string]Record) (map[string][]string, error) {
	edges := map[string][]string{}
	sonames := map[string][]string{}
	roots := []string{}
	for name := range present {
		body := fs.bodies[name]
		// Mach-O and PE executables name their dylibs and DLLs for a foreign
		// operating system; those references are never resolved against this
		// Linux rootfs, so they contribute no edge here.
		if !bytes.HasPrefix(body, []byte("\x7fELF")) {
			continue
		}
		f, err := elf.NewFile(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
			foreign, err := crossBuiltELF(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if !foreign {
				return nil, fmt.Errorf("unsupported runtime ELF architecture %s", name)
			}
			continue
		}
		if f.Section(".dynamic") != nil {
			if err := checkRuntimeLoader(fs, present, "/lib64/ld-linux-x86-64.so.2"); err != nil {
				f.Close()
				return nil, err
			}
			for candidate := range fs.index.Files {
				if candidate == "/etc/ld.so.cache" || candidate == "/etc/ld.so.preload" || strings.Contains(candidate, "/glibc-hwcaps/") {
					f.Close()
					return nil, fmt.Errorf("unsupported dynamic loader feature %s", candidate)
				}
			}
		}
		needed, err := f.ImportedLibraries()
		if err != nil {
			f.Close()
			return nil, err
		}
		sonames[name], err = f.DynString(elf.DT_SONAME)
		if err != nil {
			f.Close()
			return nil, err
		}
		if f.Type == elf.ET_EXEC {
			roots = appendUnique(roots, name)
		}
		for _, prog := range f.Progs {
			if prog.Type == elf.PT_INTERP {
				roots = appendUnique(roots, name)
				raw, err := io.ReadAll(prog.Open())
				if err != nil {
					f.Close()
					return nil, err
				}
				interpreter := strings.TrimRight(string(raw), "\x00")
				if err := checkRuntimeLoader(fs, present, interpreter); err != nil {
					f.Close()
					return nil, err
				}
				needed = append(needed, interpreter)
			}
		}
		dirs, err := runtimeDirs(f, name)
		if err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		for _, soname := range needed {
			resolved, err := resolveRuntime(fs, present, soname, dirs)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			edges[name] = appendUnique(edges[name], resolved)
		}
	}
	if err := rejectConflictingRuntimeSONAMEs(edges, sonames, roots); err != nil {
		return nil, err
	}
	return edges, nil
}

// crossBuiltELF reports whether f is an accepted ELF built for another machine
// than this image runs. Such a file has no closure here, so the record reader's
// guarantee that it loads nothing is confirmed rather than assumed: a foreign
// loader or shared dependency would have to be resolved somewhere, and this
// rootfs is not that somewhere.
func crossBuiltELF(f *elf.File) (bool, error) {
	if f.Class != elf.ELFCLASS32 || f.Machine != elf.EM_ARM {
		return false, nil
	}
	needed, err := f.ImportedLibraries()
	if err != nil {
		return false, err
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return false, fmt.Errorf("unsupported: cross-built executable needs a runtime loader")
		}
	}
	if len(needed) > 0 {
		return false, fmt.Errorf("unsupported: cross-built executable needs %s", strings.Join(needed, ", "))
	}
	return true, nil
}

// Per-object resolution cannot model glibc's reuse of already loaded objects.
// Reject conflicting canonical paths within each executable's closure, including
// DT_NEEDED dependencies. Equal bytes at different paths still have distinct owners.
func rejectConflictingRuntimeSONAMEs(edges, sonames map[string][]string, roots []string) error {
	sort.Strings(roots)
	for _, root := range roots {
		owners := map[string]string{}
		visited := map[string]bool{}
		queue := []string{root}
		for len(queue) > 0 {
			name := queue[0]
			queue = queue[1:]
			if visited[name] {
				continue
			}
			visited[name] = true
			for _, soname := range sonames[name] {
				if previous, exists := owners[soname]; exists && previous != name {
					return fmt.Errorf("conflicting runtime SONAME %s in closure of %s: %s vs %s", soname, root, previous, name)
				}
				owners[soname] = name
			}
			queue = append(queue, edges[name]...)
		}
	}
	return nil
}

// This loader's --help reports these default paths; other x86-64 loaders can differ.
const supportedRuntimeLoaderSHA256 = "sha256:606bf05526f326f0f4cd42450ff6ee0a7c9ff9391d7f37f38473874e0897e53c"

func checkRuntimeLoader(fs *filesystem, present map[string]Record, name string) error {
	resolved, err := resolvePath(fs, name)
	if err != nil {
		return err
	}
	record, known := present[resolved]
	if !known || record.SHA256 != supportedRuntimeLoaderSHA256 || digest(fs.bodies[resolved]) != supportedRuntimeLoaderSHA256 {
		return fmt.Errorf("unsupported or unknown runtime loader %s", name)
	}
	return nil
}

func runtimeDirs(f *elf.File, name string) ([]string, error) {
	dirs := []string{"/lib64", "/usr/lib64"}
	rpath, err := f.DynString(elf.DT_RPATH)
	if err != nil {
		return nil, err
	}
	if len(rpath) > 0 {
		return nil, fmt.Errorf("DT_RPATH inheritance unsupported; use DT_RUNPATH")
	}
	entries, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		return nil, err
	}
	search := []string{}
	for _, entry := range entries {
		for _, dir := range strings.Split(entry, ":") {
			dir = strings.ReplaceAll(dir, "${ORIGIN}", path.Dir(name))
			dir = strings.ReplaceAll(dir, "$ORIGIN", path.Dir(name))
			if !strings.HasPrefix(dir, "/") || strings.Contains(dir, "$") {
				return nil, fmt.Errorf("unsupported runtime search path %s", dir)
			}
			search = append(search, dir)
		}
	}
	return append(search, dirs...), nil
}

func resolveRuntime(fs *filesystem, present map[string]Record, soname string, dirs []string) (string, error) {
	candidates := []string{}
	if strings.Contains(soname, "/") {
		if !strings.HasPrefix(soname, "/") {
			return "", fmt.Errorf("relative DT_NEEDED unsupported %s", soname)
		}
		candidates = append(candidates, soname)
	} else {
		for _, dir := range dirs {
			candidates = append(candidates, path.Join(dir, soname))
		}
	}
	for _, candidate := range candidates {
		resolved, err := resolvePath(fs, candidate)
		if err != nil {
			return "", err
		}
		if _, exists := fs.index.Files[resolved]; !exists {
			continue
		}
		if _, known := present[resolved]; !known {
			return "", fmt.Errorf("unknown runtime dependency %s", resolved)
		}
		df, err := elf.NewFile(bytes.NewReader(fs.bodies[resolved]))
		if err != nil {
			return "", fmt.Errorf("runtime dependency is not ELF %s", resolved)
		}
		names, err := df.DynString(elf.DT_SONAME)
		df.Close()
		if err != nil {
			return "", err
		}
		if !strings.Contains(soname, "/") && !slices.Contains(names, soname) {
			return "", fmt.Errorf("runtime SONAME mismatch %s", resolved)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("missing runtime dependency %s", soname)
}
