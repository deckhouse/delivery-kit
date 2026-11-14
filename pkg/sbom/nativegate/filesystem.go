package nativegate

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/werf/werf/v3/pkg/sbom/shippedscope"
)

type filesystem struct {
	index      *shippedscope.FileIndex
	bodies     map[string][]byte
	executable map[string]bool
}

func servicePath(name string) bool {
	return name == "/.werf" || strings.HasPrefix(name, "/.werf/")
}

func excludeServiceFiles(index *shippedscope.FileIndex) {
	maps.DeleteFunc(index.Files, func(name string, _ shippedscope.File) bool {
		return servicePath(name)
	})
}

func readFilesystem(ctx context.Context, img v1.Image) (*filesystem, error) {
	index, err := shippedscope.IndexImageFiles(ctx, img)
	if err != nil {
		return nil, err
	}
	if index.Incomplete {
		return nil, fmt.Errorf("incomplete image index")
	}
	outsideDigests := map[string]bool{}
	for name, file := range index.Files {
		if !servicePath(name) {
			outsideDigests[file.Digest] = true
		}
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
		if servicePath(name) && !outsideDigests[entry.Digest] {
			continue
		}
		if _, exists := fs.bodies[name]; exists {
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
		// A name the suffix guard recognizes is judged on its whole body too: the text
		// a toolchain installs under a library name is only text if no byte of it says
		// otherwise, and a prefix cannot say that.
		full := servicePath(name) || nativeCandidate(prefix) || bytes.HasPrefix(prefix, []byte("#!")) || h.Mode&0o111 != 0 || binaryName(name)
		if full {
			if h.Size > 512<<20 {
				return nil, fmt.Errorf("%s: file exceeds supported inspection limit", name)
			}
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
		if servicePath(name) {
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
		if !found {
			return nil, fmt.Errorf("unreadable surviving file %s", name)
		}
	}
	excludeServiceFiles(index)
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
// reader, not this guess, decides whether the file is native at all. An archive
// is judged by the members it holds, which stand in the rest of the file.
func nativeCandidate(prefix []byte) bool {
	if nativeMagic(prefix) {
		return true
	}
	if bytes.HasPrefix(prefix, []byte(archiveMagic)) || bytes.HasPrefix(prefix, []byte(thinArchiveMagic)) {
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
	if executable || bytes.HasPrefix(body, []byte("\x7fELF")) || bytes.HasPrefix(body, []byte("MZ")) || bytes.HasPrefix(body, []byte("\x00asm")) || bytes.HasPrefix(body, []byte("!<arch>")) || bytes.HasPrefix(body, []byte("!<thin>")) {
		return true
	}

	// The name is a guess about content, and content the classifier reads as text
	// settles it: a GNU ld script is what a toolchain installs as libc.so or
	// libgcc_s_asneeded.so, and no composition is read out of text.
	return binaryName(name) && !linkerScript(body)
}

func binaryName(name string) bool {
	return strings.HasSuffix(name, ".o") || strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".a")
}
