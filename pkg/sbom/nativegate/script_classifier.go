package nativegate

import (
	"bytes"
	"unicode/utf8"
)

const shebangLimit = 256

// AS_NEEDED stands only inside GROUP or INPUT and INCLUDE takes a bare file name,
// so neither opens a script in the parenthesized form read below.
var linkerScriptDirectives = []string{"ENTRY", "EXTERN", "GROUP", "INPUT", "OUTPUT", "OUTPUT_ARCH", "OUTPUT_FORMAT", "SEARCH_DIR", "STARTUP", "TARGET"}

// Inspect the whole text, so a shebang cannot hide an appended binary payload.
func interpretedScript(body []byte, name string) bool {
	if binaryLike(body, false, name) {
		return false
	}
	line, rest, terminated := bytes.Cut(body, []byte("\n"))
	if !terminated || !bytes.HasPrefix(line, []byte("#!")) || len(line) >= shebangLimit {
		return false
	}
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 || bytes.IndexByte(body, 0x7f) >= 0 {
		return false
	}

	// A shebang alone is a header, not a script anything is attributed to.
	return len(bytes.TrimSpace(rest)) > 0
}

// plainText reports a whole body that is text: an execute bit does not make text
// a compiled artifact, so such a file is read as the same text without the bit.
func plainText(body []byte, name string) bool {
	if binaryLike(body, false, name) || nativeCandidate(body) || !utf8.Valid(body) {
		return false
	}
	for _, point := range string(body) {
		if point == '\t' || point == '\n' || point == '\r' || point == '\f' {
			continue
		}
		if point < 0x20 || point == 0x7f {
			return false
		}
	}

	return true
}

// linkerScript reports a GNU ld script: the text a toolchain installs under the name of
// a library - libc.so, libgcc_s_asneeded.so - to point the linker at what the library
// really is. Nothing is compiled into it and no composition is read out of it, so it is
// accounted for as the text it is rather than as the binary its name suggests.
//
// The whole body is read, so bytes past the opening directive cannot hide a payload.
func linkerScript(body []byte) bool {
	if !textScriptBody(body) {
		return false
	}
	rest := bytes.TrimLeft(body, " \t\r\n")
	for bytes.HasPrefix(rest, []byte("/*")) {
		_, after, closed := bytes.Cut(rest[2:], []byte("*/"))
		if !closed {
			return false
		}
		rest = bytes.TrimLeft(after, " \t\r\n")
	}
	for _, directive := range linkerScriptDirectives {
		if !bytes.HasPrefix(rest, []byte(directive)) {
			continue
		}
		if bytes.HasPrefix(bytes.TrimLeft(rest[len(directive):], " \t\r\n"), []byte("(")) {
			return true
		}
	}

	return false
}

func textScriptBody(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, point := range string(body) {
		if point == '\t' || point == '\n' || point == '\r' {
			continue
		}
		if point < 0x20 || point == 0x7f {
			return false
		}
	}

	return true
}
