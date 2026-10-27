package nativegate

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func (i *inspector) archiveMember(input LinkInput) error {
	archive := input.Archive
	members, ok := i.archiveIndexes[archive.SHA256]
	if !ok {
		body, ok := i.archives[strings.TrimRight(i.image.MetaDir, "/")+"/archives/"+strings.TrimPrefix(archive.SHA256, "sha256:")+".a"]
		if !ok || digest(body) != archive.SHA256 {
			return fmt.Errorf("missing/changed original archive evidence %s", archive.Path)
		}
		if !bytes.HasPrefix(body, []byte("!<arch>\n")) {
			return fmt.Errorf("unsupported archive format %s", archive.Path)
		}
		var err error
		members, err = archiveIndex(body)
		if err != nil {
			return err
		}
		if i.archiveIndexes == nil {
			i.archiveIndexes = map[string]map[string][]string{}
		}
		i.archiveIndexes[archive.SHA256] = members
	}
	hashes := members[input.Member]
	if len(hashes) != 1 {
		return fmt.Errorf("missing/ambiguous archive member %s(%s)", archive.Path, input.Member)
	}
	if hashes[0] != input.SHA256 {
		return fmt.Errorf("archive member content mismatch %s(%s)", archive.Path, input.Member)
	}
	return nil
}

func archiveIndex(body []byte) (map[string][]string, error) {
	members := map[string][]string{}
	names := []byte{}
	for offset := 8; offset < len(body); {
		if offset+60 > len(body) {
			return nil, fmt.Errorf("truncated archive")
		}
		header := body[offset : offset+60]
		if string(header[58:60]) != "`\n" {
			return nil, fmt.Errorf("invalid archive header")
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil || size < 0 || size > len(body)-offset-60 {
			return nil, fmt.Errorf("invalid archive member size")
		}
		name := strings.TrimSpace(string(header[:16]))
		data := body[offset+60 : offset+60+size]
		switch {
		case name == "//":
			names = data
		case name == "/" || name == "/SYM64/":
		case strings.HasPrefix(name, "#1/"):
			return nil, fmt.Errorf("unsupported BSD archive member")
		default:
			if strings.HasPrefix(name, "/") {
				pos, err := strconv.Atoi(strings.TrimPrefix(name, "/"))
				if err != nil || pos < 0 || pos >= len(names) {
					return nil, fmt.Errorf("invalid archive name reference")
				}
				end := bytes.IndexByte(names[pos:], '\n')
				if end < 0 {
					return nil, fmt.Errorf("unterminated archive name")
				}
				name = string(names[pos : pos+end])
			}
			name = strings.TrimSuffix(name, "/")
			members[name] = append(members[name], digest(data))
		}
		offset += 60 + size
		if offset%2 != 0 {
			offset++
		}
	}
	return members, nil
}
