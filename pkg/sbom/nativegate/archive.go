package nativegate

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func (i *inspector) archiveMember(input LinkInput) error {
	archive := input.Archive
	body, ok := i.archives[strings.TrimRight(i.image.MetaDir, "/")+"/archives/"+strings.TrimPrefix(archive.SHA256, "sha256:")+".a"]
	if !ok || digest(body) != archive.SHA256 {
		return fmt.Errorf("missing/changed original archive evidence %s", archive.Path)
	}
	if !bytes.HasPrefix(body, []byte("!<arch>\n")) {
		return fmt.Errorf("unsupported archive format %s", archive.Path)
	}
	names := []byte{}
	matches := 0
	for offset := 8; offset < len(body); {
		if offset+60 > len(body) {
			return fmt.Errorf("truncated archive")
		}
		header := body[offset : offset+60]
		if string(header[58:60]) != "`\n" {
			return fmt.Errorf("invalid archive header")
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil || size < 0 || size > len(body)-offset-60 {
			return fmt.Errorf("invalid archive member size")
		}
		name := strings.TrimSpace(string(header[:16]))
		data := body[offset+60 : offset+60+size]
		switch {
		case name == "//":
			names = data
		case name == "/" || name == "/SYM64/":
		case strings.HasPrefix(name, "#1/"):
			return fmt.Errorf("unsupported BSD archive member")
		default:
			if strings.HasPrefix(name, "/") {
				pos, err := strconv.Atoi(strings.TrimPrefix(name, "/"))
				if err != nil || pos < 0 || pos >= len(names) {
					return fmt.Errorf("invalid archive name reference")
				}
				end := bytes.IndexByte(names[pos:], '\n')
				if end < 0 {
					return fmt.Errorf("unterminated archive name")
				}
				name = string(names[pos : pos+end])
			}
			name = strings.TrimSuffix(name, "/")
			if name == input.Member {
				matches++
				if digest(data) != input.SHA256 {
					return fmt.Errorf("archive member content mismatch %s(%s)", archive.Path, name)
				}
			}
		}
		offset += 60 + size
		if offset%2 != 0 {
			offset++
		}
	}
	if matches != 1 {
		return fmt.Errorf("missing/ambiguous archive member %s(%s)", archive.Path, input.Member)
	}
	return nil
}
