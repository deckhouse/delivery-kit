package nativegate

import (
	"bytes"
	"debug/elf"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	archiveMagic     = "!<arch>\n"
	thinArchiveMagic = "!<thin>\n"
	archiveHeaderLen = 60
)

// archiveMember is one ordinary member of an ar. The symbol and name tables an
// archive carries name no content of their own, so they take no ordinal: index
// is the zero-based ordinal of the ordinary members alone, which is the number
// the contract's archive.index states.
type archiveMember struct {
	name  string
	body  []byte
	index int
}

// readArchive reads what a shipped ar is made of. The contract gives an archive
// no artifact kind of its own - it knows one only as an input a link selects
// members out of - so there is no record to read here and nothing to exempt: the
// archive is the members it holds, each of which answers for itself exactly as a
// relocatable object shipped on its own does, and the composition of the archive
// is the union of theirs. One member that cannot answer refuses the whole file,
// because what a link would take out of it is not this gate's to guess.
//
// An archive holding no member at all - the stub libdl.a, libpthread.a and
// librt.a glibc still installs - holds no code either. It is accepted with no
// components and recorded as read, so that nothing downstream has to decide what
// an unrecorded file at that path means.
func (i *inspector) readArchive(record *Record, body []byte) error {
	if bytes.HasPrefix(body, []byte(thinArchiveMagic)) {
		return fmt.Errorf("unsupported: a thin archive holds no member bytes, only names of files outside it")
	}
	members, err := archiveMembers(body)
	if err != nil {
		return err
	}
	evidence := ArchiveEvidence{Members: []ArchiveMember{}}
	for _, member := range members {
		if !relocatableObject(member.body) {
			return fmt.Errorf("no-data: archive member %s (index %d) is no relocatable object carrying a record of its build", member.name, member.index)
		}
		read, _, err := i.inspect(member.body)
		if err != nil {
			return fmt.Errorf("%w (archive member %s, index %d)", err, member.name, member.index)
		}
		evidence.Members = append(evidence.Members, ArchiveMember{
			Name: member.name, Index: member.index, SHA256: read.SHA256,
			Profile: read.Profile, Composition: read.Composition, Components: read.Components,
		})
		record.Components = appendUnique(record.Components, read.Components...)
		for _, tool := range read.Tools {
			if !slices.Contains(record.Tools, tool) {
				record.Tools = append(record.Tools, tool)
			}
		}
	}
	sort.Strings(record.Components)
	record.Archive = &evidence
	return nil
}

func relocatableObject(body []byte) bool {
	f, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return false
	}
	defer f.Close()

	return f.Type == elf.ET_REL
}

// archiveMembers reads the ordinary members of a GNU or BSD ar. Bytes that do
// not read as members at all are invalid rather than content of unknown kind:
// an archive this reader cannot walk is one whose members it cannot name.
func archiveMembers(body []byte) ([]archiveMember, error) {
	rest := body[len(archiveMagic):]
	members := []archiveMember{}
	var names []byte
	for len(rest) > 0 {
		if len(rest) < archiveHeaderLen {
			return nil, fmt.Errorf("invalid: the archive ends inside the header of member %d", len(members))
		}
		header := rest[:archiveHeaderLen]
		if string(header[58:archiveHeaderLen]) != "`\n" {
			return nil, fmt.Errorf("invalid: the header of member %d is not terminated", len(members))
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid: the header of member %d states no readable size", len(members))
		}
		rest = rest[archiveHeaderLen:]
		if int64(len(rest)) < size {
			return nil, fmt.Errorf("invalid: member %d extends past the end of the archive", len(members))
		}
		data := rest[:size]
		rest = rest[size:]
		// Members are aligned on an even boundary; the last one need not carry
		// the padding byte it would be followed by.
		if size%2 == 1 && len(rest) > 0 {
			rest = rest[1:]
		}
		name, data, err := archiveMemberName(strings.TrimRight(string(header[:16]), " "), data, &names)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		members = append(members, archiveMember{name: name, body: data, index: len(members)})
	}

	return members, nil
}

// archiveMemberName resolves the name an ar header spells and returns the bytes
// the member itself holds. An index table - the symbol tables of both flavors
// and the GNU name table - is reported as an empty name: it is skipped as the
// bookkeeping it is, and never as a member that happens to hold no record.
func archiveMemberName(raw string, data []byte, names *[]byte) (string, []byte, error) {
	switch {
	case raw == "/" || raw == "/SYM64/":
		return "", nil, nil
	case raw == "//":
		*names = data

		return "", nil, nil
	case strings.HasPrefix(raw, "#1/"):
		length, err := strconv.Atoi(raw[3:])
		if err != nil || length < 0 || length > len(data) {
			return "", nil, fmt.Errorf("invalid: an archive member states a name length its bytes do not hold")
		}
		raw = strings.TrimRight(string(data[:length]), "\x00")
		data = data[length:]
	case strings.HasPrefix(raw, "/"):
		offset, err := strconv.Atoi(raw[1:])
		if err != nil || offset < 0 || offset >= len(*names) {
			return "", nil, fmt.Errorf("invalid: an archive member names no entry of the archive's name table")
		}
		entry := (*names)[offset:]
		if end := bytes.IndexAny(entry, "/\n"); end >= 0 {
			entry = entry[:end]
		}
		raw = string(entry)
	default:
		raw = strings.TrimSuffix(raw, "/")
	}
	// The BSD symbol table is an ordinary member by its header and a table by its
	// name, which a long-name header spells out of the member's own bytes.
	if raw == "__.SYMDEF" || raw == "__.SYMDEF SORTED" || raw == "__.SYMDEF_64" {
		return "", nil, nil
	}
	if raw == "" {
		return "", nil, fmt.Errorf("invalid: an archive member carries no name")
	}

	return raw, data, nil
}
