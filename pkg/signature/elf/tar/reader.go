package tar

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
)

// elfHeaderPeekSize is the number of leading bytes needed to classify an ELF
// file: 4-byte magic, EI_CLASS (off.4), EI_DATA (off.5) and e_machine (off.18,
// 2 bytes). 20 bytes covers up to and including e_machine.
const elfHeaderPeekSize = 20

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
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	prefix = prefix[:n]

	// ponytail: MultiReader stitches the peeked prefix back before the rest of
	// the tar body — bounded memory, no full-file buffering.
	etr.body = io.MultiReader(bytes.NewReader(prefix), etr.tr)

	return newHeader(hdr, isELFPrefix(prefix)), nil
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

// isELFPrefix classifies an ELF file from its leading header bytes. It matches
// the previous debug/elf.NewFile-based behavior for the supported machines
// (EM_386, EM_X86_64) without reading the whole file body.
func isELFPrefix(b []byte) bool {
	if len(b) < elfHeaderPeekSize {
		return false
	}

	// Magic: 0x7f 'E' 'L' 'F'.
	if b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' {
		return false
	}

	// EI_CLASS (off.4): must be 32- or 64-bit.
	switch elf.Class(b[elf.EI_CLASS]) {
	case elf.ELFCLASS32, elf.ELFCLASS64:
	default:
		return false
	}

	// EI_DATA (off.5) selects endianness for e_machine (off.18, 2 bytes).
	var order binary.ByteOrder
	switch elf.Data(b[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return false
	}

	switch elf.Machine(order.Uint16(b[18:20])) {
	case elf.EM_386, elf.EM_X86_64:
		return true
	default:
		return false
	}
}
