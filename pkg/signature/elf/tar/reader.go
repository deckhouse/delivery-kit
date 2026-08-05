package tar

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
)

// elfHeaderPeekSize is the number of leading bytes needed to classify an ELF
// file: 4-byte magic, EI_CLASS (off.4), EI_DATA (off.5), EI_VERSION (off.6),
// e_machine (off.18, 2 bytes) and e_version (off.20, 4 bytes). 24 bytes covers
// up to and including e_version.
const elfHeaderPeekSize = 24

// Reader is a wrapper around tar.Reader that works almost like tar.Reader with one difference:
// 1. It returns header.IsELF boolean field when no error.
type Reader struct {
	tr   *tar.Reader
	body io.Reader
}

func NewReader(tr *tar.Reader) *Reader {
	return &Reader{tr: tr}
}

// Next works almost like tar.Reader.Next() with one difference:
// 1. It returns header.IsELF boolean field when no error.
//
// ELF classification reads only a small header prefix (elfHeaderPeekSize
// bytes); the peeked bytes are stitched back in front of the remaining tar
// stream so the caller can Read the full body without loss.
func (etr *Reader) Next() (*Header, error) {
	etr.body = nil

	hdr, err := etr.tr.Next()
	if err != nil {
		return nil, err
	}

	if hdr.Typeflag != tar.TypeReg {
		return newHeader(hdr, false), nil
	}

	prefix := make([]byte, elfHeaderPeekSize)
	n, err := io.ReadFull(etr.tr, prefix)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	prefix = prefix[:n]

	etr.body = io.MultiReader(bytes.NewReader(prefix), etr.tr)

	return newHeader(hdr, isELFPrefix(prefix, hdr.Size)), nil
}

func (etr *Reader) Read(p []byte) (n int, err error) {
	if etr.body != nil {
		return etr.body.Read(p)
	}
	return etr.tr.Read(p)
}

// Header is a wrapper around tar.Header with an IsELF boolean field
type Header struct {
	*tar.Header

	IsELF bool
}

func newHeader(hdr *tar.Header, isELF bool) *Header {
	return &Header{hdr, isELF}
}

// ELF header sizes (bytes) for the two supported classes. A real ELF file is
// at least this large; debug/elf.NewFile rejects anything smaller, so we use it
// to keep truncated files (valid ident, no real body) out of the signer.
const (
	ehsize32 = 52
	ehsize64 = 64
)

// isELFPrefix classifies an ELF file from its leading header bytes and total
// size. It matches the previous debug/elf.NewFile-based behavior for the
// supported machines (EM_386, EM_X86_64) without reading the whole file body.
func isELFPrefix(b []byte, size int64) bool {
	if len(b) < elfHeaderPeekSize {
		return false
	}

	// Magic: 0x7f 'E' 'L' 'F'.
	if b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' {
		return false
	}

	// EI_CLASS (off.4): must be 32- or 64-bit, and the file must be at least as
	// large as the corresponding ELF header (rejects truncated non-binaries).
	switch elf.Class(b[elf.EI_CLASS]) {
	case elf.ELFCLASS32:
		if size < ehsize32 {
			return false
		}
	case elf.ELFCLASS64:
		if size < ehsize64 {
			return false
		}
	default:
		return false
	}

	// EI_DATA (off.5) selects endianness for the numeric header fields.
	var order binary.ByteOrder
	switch elf.Data(b[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return false
	}

	// EI_VERSION (off.6) and e_version (off.20) must be EV_CURRENT. This keeps
	// detection conservative so files that merely start with the ELF magic but
	// are not real binaries are not sent to the signer.
	if elf.Version(b[elf.EI_VERSION]) != elf.EV_CURRENT {
		return false
	}
	if elf.Version(order.Uint32(b[20:24])) != elf.EV_CURRENT {
		return false
	}

	switch elf.Machine(order.Uint16(b[18:20])) {
	case elf.EM_386, elf.EM_X86_64:
		return true
	default:
		return false
	}
}
