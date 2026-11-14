package nativegate

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
)

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

func runtimeDependencies(fs *filesystem, present map[string]Record, partial bool) (map[string][]string, []string, error) {
	edges := map[string][]string{}
	sonames := map[string][]string{}
	roots := []string{}
	unresolved := []string{}
	loader, err := imageRuntimeLoader(fs, present, partial)
	if err != nil {
		return nil, nil, err
	}
	// A partial runtime is a part of a closure, not a closure. An image holding the
	// loader its own executables name holds the file every search of theirs starts
	// from, and states their closure itself; the declaration would then excuse
	// nothing but the absences of an image that has none to excuse.
	if partial && loader != nil {
		return nil, nil, fmt.Errorf("invalid: this image declares a partial runtime but holds the runtime loader %s its executables name, so the closure of those executables is the one this image states", loader.path)
	}
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
			return nil, nil, err
		}
		if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
			foreign, err := crossBuiltELF(f)
			f.Close()
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			if !foreign {
				return nil, nil, fmt.Errorf("unsupported runtime ELF architecture %s", name)
			}
			continue
		}
		if f.Section(".dynamic") != nil {
			if !partial {
				if err := requireRuntimeLoader(loader, name); err != nil {
					f.Close()
					return nil, nil, err
				}
			}
			for candidate := range fs.index.Files {
				if strings.Contains(candidate, "/glibc-hwcaps/") {
					f.Close()
					return nil, nil, fmt.Errorf("unsupported dynamic loader feature %s", candidate)
				}
			}
			// The preload file is opened by path, and a path leads where the
			// image's links say: one reached through a link, or standing in an
			// /etc that is itself a link, is the same file. The cache is refused
			// where the loader's own bytes name it, which is not always here.
			for _, feature := range refusedLoaderFiles(partial, loader) {
				held, err := holdsFile(fs, feature)
				if err != nil {
					f.Close()

					return nil, nil, err
				}
				if held {
					f.Close()

					return nil, nil, fmt.Errorf("unsupported dynamic loader feature %s", feature)
				}
			}
		}
		needed, err := f.ImportedLibraries()
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		sonames[name], err = f.DynString(elf.DT_SONAME)
		if err != nil {
			f.Close()
			return nil, nil, err
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
					return nil, nil, err
				}
				// Which file this name lands on, and whether that file is
				// the loader it claims to be, was settled for the whole
				// image before any of this: an image whose executables name
				// two different files never reaches here.
				interpreter := strings.TrimRight(string(raw), "\x00")
				needed = append(needed, interpreter)
			}
		}
		dirs, err := runtimeDirs(f, name, loader)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		f.Close()
		for _, soname := range needed {
			resolved, err := resolveRuntime(fs, present, soname, dirs)
			if err != nil {
				var absent missingRuntimeDependencyError
				// The one absence a partial runtime excuses: a name no file of
				// this image answers to. A file that does answer it is read,
				// and refused, exactly as in any other image.
				if partial && errors.As(err, &absent) {
					unresolved = appendUnique(unresolved, absent.soname)

					continue
				}

				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			edges[name] = appendUnique(edges[name], resolved)
		}
	}
	if err := rejectConflictingRuntimeSONAMEs(edges, sonames, roots); err != nil {
		return nil, nil, err
	}
	// Nothing of this image's closure stands outside it, so the declaration excused
	// nothing and describes an image this is not.
	if partial && len(unresolved) == 0 {
		return nil, nil, fmt.Errorf("invalid: this image declares a partial runtime, and every runtime name its files state resolves inside it")
	}

	return edges, unresolved, nil
}

// crossBuiltELF reports whether f is an accepted ELF built for another machine
// than this image runs. Such a file has no closure here, so the record reader's
// guarantee that it loads nothing is confirmed rather than assumed: a foreign
// loader or shared dependency would have to be resolved somewhere, and this
// rootfs is not that somewhere.
//
// A file that would load something is refused rather than passed over, and the
// refusal names what it would have loaded. The loader this image knows how to
// read a closure through is an x86-64 one, so nothing is resolved for a machine
// it cannot run; until that model answers for another machine, a cross-built
// file that needs anything at all is beyond what DK can state.
func crossBuiltELF(f *elf.File) (bool, error) {
	machine := ""
	switch {
	case f.Class == elf.ELFCLASS32 && f.Machine == elf.EM_ARM:
		machine = "linux/arm"
	case f.Class == elf.ELFCLASS64 && f.Machine == elf.EM_AARCH64:
		machine = "linux/arm64"
	default:
		return false, nil
	}
	needed, err := f.ImportedLibraries()
	if err != nil {
		return false, err
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return false, fmt.Errorf("unsupported: %s executable needs a runtime loader, and this image resolves none for that machine", machine)
		}
	}
	if len(needed) > 0 {
		return false, fmt.Errorf("unsupported: %s executable needs %s, and this image resolves none for that machine", machine, strings.Join(needed, ", "))
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

// runtimeDirs is where this file's needed objects are looked for: what it asks for
// itself, then the directories the image's loader was built to search.
func runtimeDirs(f *elf.File, name string, loader *loaderModel) ([]string, error) {
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
	// A file with no dynamic section names nothing and is searched for nothing; such
	// an image need not hold a loader at all. A partial runtime whose loader stands in
	// another image is the other case this reaches: what it asks for itself is all
	// there is to search, because the directories a loader searches are read out of
	// that loader and out of nothing else - a default list would be a guess, and a
	// guessed directory resolves a name to the wrong file in silence.
	if loader == nil {
		return search, nil
	}

	return append(search, loader.dirs...), nil
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
	return "", missingRuntimeDependencyError{soname: soname}
}
