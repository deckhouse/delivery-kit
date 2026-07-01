package main

import (
	"archive/tar"
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
)

type Reader struct {
	tr       *tar.Reader
	peekBuf  []byte
	peekLen  int
	peekRead int
}

func NewReader(tr *tar.Reader) *Reader {
	return &Reader{
		tr:      tr,
		peekBuf: make([]byte, 64), // enough for ELF header
	}
}

func (r *Reader) Next() (*tar.Header, bool, error) {
	hdr, err := r.tr.Next()
	r.peekLen = 0
	r.peekRead = 0

	if err != nil {
		return nil, false, err
	}

	if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 {
		return hdr, false, nil
	}

	// Try to read first 64 bytes
	readLen := 64
	if hdr.Size < 64 {
		readLen = int(hdr.Size)
	}

	n, err := io.ReadFull(r.tr, r.peekBuf[:readLen])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return hdr, false, err
	}
	r.peekLen = n

	isELF := parseElfMachine(r.peekBuf[:n])

	return hdr, isELF, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.peekRead < r.peekLen {
		n := copy(p, r.peekBuf[r.peekRead:r.peekLen])
		r.peekRead += n
		return n, nil
	}
	return r.tr.Read(p)
}

func parseElfMachine(b []byte) bool {
	if len(b) < 18 || string(b[:4]) != "\x7fELF" {
		return false
	}
	
	// Ensure we can read Class and Machine (up to byte 19)
	if len(b) < 20 {
	    return false // need at least 20 bytes for machine type
	}

	class := elf.Class(b[elf.EI_CLASS])
	data := elf.Data(b[elf.EI_DATA])
	var machine uint16
	if class == elf.ELFCLASS32 || class == elf.ELFCLASS64 {
		if data == elf.ELFDATA2LSB {
			machine = uint16(b[18]) | uint16(b[19])<<8
		} else if data == elf.ELFDATA2MSB {
			machine = uint16(b[19]) | uint16(b[18])<<8
		} else {
		    return false
		}
	} else {
	    return false
	}
	
	switch elf.Machine(machine) {
	case elf.EM_386, elf.EM_X86_64:
		return true
	default:
		return false
	}
}

func main() {
    fmt.Println("works")
}
