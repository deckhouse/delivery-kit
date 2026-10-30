package nativegate

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// A loader is read the way everything else in a strict image is read: as the file it
// is, rather than as a name DK was told to trust. Two things are asked of it.
//
// The first is that it be accounted for. It is an ordinary mandatory file of the image
// and a compiled one, so it carries a build record or an original binding like any other
// ELF, and an image whose loader nobody can account for has not said what it runs.
//
// The second is where it looks. A dynamic executable names its loader and its needed
// objects; which file each name resolves to is the loader's own affair, decided by the
// directories it was built with. Those directories are in its bytes - glibc's rtld holds
// its SYSTEM_DIRS as a run of NUL-terminated absolute paths, each ending in a slash, in
// read-only data - and reading them there is the only way to state this image's closure
// rather than a guess about it. A loader whose directories cannot be read unambiguously
// is answered with no data: a wrong directory list does not fail loudly, it resolves a
// name to the wrong file and says nothing.
//
// Every path in these strings ends in a slash, which is what tells a directory from the
// other absolute paths a loader holds - its own name, /etc/ld.so.cache, /proc entries.
var (
	loaderDirectory = regexp.MustCompile(`\A/[\x20-\x7e]*/\z`)
	loaderCacheFile = regexp.MustCompile(`\A/[\x20-\x7e]*/ld\.so\.cache\z`)
)

// loaderModel is what the bytes of a loader say about the way it resolves a name.
type loaderModel struct {
	// path is where in this image the loader stands, after symlinks.
	path string
	// dirs are the directories it searches when a name has no slash in it, in the
	// order it searches them, with the trailing slash removed.
	dirs []string
	// cache is the file it would consult before searching those directories.
	cache string
}

// readLoaderModel takes the search directories and the cache path out of a loader's
// read-only data. It answers an error when what it finds is not one unambiguous reading.
func readLoaderModel(body []byte, path string) (*loaderModel, error) {
	f, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("no-data: the runtime loader %s is not an ELF file this image can read", path)
	}
	defer f.Close()

	dirs, caches := []string{}, []string{}
	for _, section := range f.Sections {
		// Read-only allocated data, which is where a loader keeps these strings,
		// named as such. What a loader may rewrite at run time, or execute, is not
		// a statement about how it was built, and the section's own name is the
		// thing that says which data this is - a toolchain is free to set flags
		// this does not expect beside those.
		if section.Type != elf.SHT_PROGBITS ||
			section.Flags&(elf.SHF_WRITE|elf.SHF_EXECINSTR) != 0 ||
			section.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if section.Name != ".rodata" && !strings.HasPrefix(section.Name, ".rodata.") {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("no-data: the read-only data of the runtime loader %s cannot be read: %w", path, err)
		}
		for _, candidate := range bytes.Split(data, []byte{0}) {
			text := string(candidate)
			switch {
			case loaderCacheFile.MatchString(text):
				caches = appendUnique(caches, text)
			case loaderDirectory.MatchString(text):
				dirs = appendUnique(dirs, strings.TrimSuffix(text, "/"))
			}
		}
	}

	switch {
	case len(dirs) == 0:
		return nil, fmt.Errorf("no-data: the runtime loader %s states no search directories this image can read", path)
	case len(caches) == 0:
		// A loader that names no cache file may still read one; with no cache to
		// look for, an image holding one could be resolved past it unnoticed.
		return nil, fmt.Errorf("no-data: the runtime loader %s states no cache file this image can read", path)
	case len(caches) > 1:
		return nil, fmt.Errorf("no-data: the runtime loader %s states %d cache files (%s), and which it reads is not settled",
			path, len(caches), strings.Join(caches, ", "))
	}
	// The order is the order the loader holds them in, which is the order it searches
	// them: of two files answering one name, the one it would load is the one in the
	// earlier directory, and a sorted list would name the other.
	return &loaderModel{path: path, dirs: dirs, cache: caches[0]}, nil
}

// checkRuntimeLoader resolves the interpreter a dynamic executable names, requires the
// file it lands on to be one this build accounts for, and reads out of that file the
// directories it searches.
//
// The name must resolve to the loader itself. A file standing where the interpreter
// says, that is some other package's or no package's, is refused rather than taken at
// its position: what runs the executable is the file at the end of that path, and an
// image where that file is unaccounted for runs something nobody described.
func checkRuntimeLoader(fs *filesystem, present map[string]Record, resolved string, declared []string) (*loaderModel, error) {
	body, held := fs.bodies[resolved]
	if !held {
		return nil, fmt.Errorf("missing runtime loader %s", resolved)
	}
	record, known := present[resolved]
	if !known {
		return nil, fmt.Errorf("unknown runtime loader %s", resolved)
	}
	if record.SHA256 != digest(body) {
		return nil, fmt.Errorf("hash-mismatch: the runtime loader %s is not the file its record describes", resolved)
	}

	// The file standing at the end of that path must be the loader the executables
	// asked for, and not merely the file that happens to stand there. A loader states
	// its own name as its SONAME, which is the same thing this gate asks of every
	// object it resolves: a library of some other package, linked into the
	// interpreter's path, answers to a different name and is refused rather than run
	// with.
	//
	// It is asked against the names the executables wrote, not against the name of the
	// file they led to. Those differ in both directions, and both are ordinary: a
	// glibc before 2.34 ships the loader as `ld-2.31.so` with `ld-linux-x86-64.so.2`
	// pointing at it, which answers truly to the name it was asked for; and a leaf
	// symlink from the interpreter's name onto some other library would otherwise be
	// judged by that library's own name and let through.
	if err := requireLoaderSONAME(body, declared, resolved); err != nil {
		return nil, err
	}

	model, err := readLoaderModel(body, resolved)
	if err != nil {
		return nil, err
	}
	// The cache answers before the directories do, so an image holding one is an
	// image whose closure this model cannot state. Reading it is a thing DK could
	// learn to do; ignoring it is not.
	//
	// The loader opens a path, and what a path leads to is the image's affair: a cache
	// reached through a link, or standing in an /etc that is itself a link, is the
	// same cache.
	if held, err := holdsFile(fs, model.cache); err != nil {
		return nil, err
	} else if held {
		return nil, fmt.Errorf("unsupported dynamic loader feature %s", model.cache)
	}

	return model, nil
}

// imageRuntimeLoader settles, once for the image, which file its dynamic executables
// run under and where that file looks.
//
// The executables name it: each PT_INTERP is resolved through this image's symlinks, and
// they must all land on one file. Two loaders in one image would mean two closures, and
// which of them a given shared object belongs to is not a thing this model can say.
//
// An image with dynamic files and no executable naming a loader states no closure at all,
// and is answered with no data rather than with the directories some other image's loader
// would have used.
func imageRuntimeLoader(fs *filesystem, present map[string]Record) (*loaderModel, error) {
	declared := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(present)) {
		body := fs.bodies[name]
		if !bytes.HasPrefix(body, []byte("\x7fELF")) {
			continue
		}
		f, err := elf.NewFile(bytes.NewReader(body))
		if err != nil {
			continue
		}
		// A file built for another machine runs under a loader of that machine's,
		// which this image resolves nothing for; it is answered where cross-built
		// files are answered, and says nothing about this image's closure.
		if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
			f.Close()

			continue
		}
		for _, prog := range f.Progs {
			if prog.Type != elf.PT_INTERP {
				continue
			}
			raw, err := io.ReadAll(prog.Open())
			if err != nil {
				f.Close()

				return nil, fmt.Errorf("%s: %w", name, err)
			}
			interp := strings.TrimRight(string(raw), "\x00")
			resolved, err := resolvePath(fs, interp)
			if err != nil {
				f.Close()

				return nil, fmt.Errorf("%s: %w", name, err)
			}
			declared[resolved] = appendUnique(declared[resolved], interp)
		}
		f.Close()
	}

	named := slices.Sorted(maps.Keys(declared))
	switch len(named) {
	case 0:
		return nil, nil
	case 1:
		return checkRuntimeLoader(fs, present, named[0], declared[named[0]])
	default:
		return nil, fmt.Errorf("no-data: this image names %d runtime loaders (%s), and which closure each of its files belongs to is not settled",
			len(named), strings.Join(named, ", "))
	}
}

// holdsFile answers whether the image holds the file that path leads to, following the
// links on the way and at the end. A link leading nowhere holds no file.
func holdsFile(fs *filesystem, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	resolved, err := resolvePath(fs, name)
	if err != nil {
		return false, err
	}
	_, held := fs.index.Files[resolved]

	return held, nil
}

// requireRuntimeLoader refuses a dynamic file in an image whose loader is unknown. A
// shared object names no interpreter of its own; what resolves its DT_NEEDED entries is
// the loader of whatever runs it, and an image where nothing names one has not said.
func requireRuntimeLoader(loader *loaderModel, name string) error {
	if loader == nil {
		return fmt.Errorf("no-data: %s is dynamically linked and no executable of this image names a runtime loader, so the directories its dependencies are searched in are not stated; an image whose executables are static PIEs, which name none, is not supported", name)
	}

	return nil
}

func requireLoaderSONAME(body []byte, declared []string, resolved string) error {
	f, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("the runtime loader %s is not an ELF file this image can read", resolved)
	}
	defer f.Close()

	sonames, err := f.DynString(elf.DT_SONAME)
	if err != nil {
		return err
	}
	for _, interp := range declared {
		expected := path.Base(interp)
		if !slices.Contains(sonames, expected) {
			return fmt.Errorf("runtime loader SONAME mismatch %s: it is named as %s and calls itself %s",
				resolved, expected, strings.Join(append([]string{}, sonames...), ", "))
		}
	}

	return nil
}
