package nativegate

import (
	"bytes"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

const shebangLimit = 256

const envInterpreter = "/usr/bin/env"

var knownInterpreters = []string{"ash", "bash", "dash", "node", "python", "python3", "sh"}

// Inspect the whole text, so a shebang cannot hide an appended binary payload.
func interpretedScript(body []byte, name string) bool {
	if binaryLike(body, false, name) {
		return false
	}
	line, rest, terminated := bytes.Cut(body, []byte("\n"))
	if !terminated || !bytes.HasPrefix(line, []byte("#!")) || len(line) >= shebangLimit {
		return false
	}
	if !textScriptBody(body) {
		return false
	}
	if !shebangInterpreter(string(line)) {
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

// Quoted or escaped interpreter syntax is outside this conservative classifier.
func shebangInterpreter(line string) bool {
	rest := strings.TrimSuffix(strings.TrimPrefix(line, "#!"), "\r")
	for n := 0; n < len(rest); n++ {
		if rest[n] != '\t' && (rest[n] < 0x20 || rest[n] > 0x7e) {
			return false
		}
	}
	if strings.ContainsAny(rest, `'"\`) {
		return false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return false
	}
	if fields[0] == envInterpreter {
		return envShebangInterpreter(fields[1:])
	}
	if !strings.HasPrefix(fields[0], "/") || path.Clean(fields[0]) != fields[0] {
		return false
	}

	return slices.Contains(knownInterpreters, path.Base(fields[0]))
}

// Without -S, env receives the remainder as one executable name.
func envShebangInterpreter(arguments []string) bool {
	split := len(arguments) > 0 && arguments[0] == "-S"
	if split {
		arguments = arguments[1:]
	}
	if len(arguments) == 0 || (!split && len(arguments) != 1) {
		return false
	}

	return !strings.Contains(arguments[0], "/") && slices.Contains(knownInterpreters, arguments[0])
}
