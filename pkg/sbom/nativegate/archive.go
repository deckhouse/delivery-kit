package nativegate

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	archiveMagic      = "!<arch>\n"
	thinArchiveMagic  = "!<thin>\n"
	archiveHeaderLen  = 60
	archiveNameTable  = "//"
	archiveNameEnding = "/\n"
)

// archiveMember is one ordinary member of an ar. The index tables an archive
// carries name no content of their own, so they take no ordinal: index is the
// zero-based ordinal of the ordinary members alone, which is the number the
// contract's archive.index states.
type archiveMember struct {
	name  string
	body  []byte
	index int
}

// rawEntry is one header of the archive and the bytes it sizes, before anything
// is decided about what that header names. offset is where the header itself
// stands in the file, which is what the symbol index points at, and entry is the
// ordinal of the header among all of them, index tables included.
type rawEntry struct {
	name   string
	data   []byte
	offset int
	entry  int
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
//
// Where a header stands decides what it is. A linker reads the symbol index as
// the first entry of the archive and the name table before the members that
// spell their names through it; a header carrying one of those names anywhere
// else is a member like any other to bfd, which links it under --whole-archive
// and under any symbol it defines. Such a header is refused rather than skipped
// as bookkeeping that could hide a member.
func archiveMembers(body []byte) ([]archiveMember, error) {
	entries, err := archiveEntries(body)
	if err != nil {
		return nil, err
	}
	var index *rawEntry
	var names []byte
	nameStarts := map[int]bool{}
	namesSeen := false
	members := []archiveMember{}
	headers := map[int]bool{}
	for position := range entries {
		entry := entries[position]
		if entry.name == archiveNameTable {
			if namesSeen || len(members) > 0 {
				return nil, outOfPlace(entry)
			}
			if nameStarts, err = archiveNameStarts(entry.data); err != nil {
				return nil, err
			}
			names, namesSeen = entry.data, true

			continue
		}
		name, data := entry.name, entry.data
		if !archiveIndexName(name) {
			if name, data, err = archiveMemberName(entry, names, nameStarts); err != nil {
				return nil, err
			}
		}
		if archiveIndexName(name) {
			if entry.entry != 0 {
				return nil, outOfPlace(entry)
			}
			index = &rawEntry{name: name, data: data, offset: entry.offset, entry: entry.entry}

			continue
		}
		headers[entry.offset] = true
		members = append(members, archiveMember{name: name, body: data, index: len(members)})
	}
	if index != nil {
		if err := checkArchiveIndex(*index, headers); err != nil {
			return nil, err
		}
	}

	return members, nil
}

func outOfPlace(entry rawEntry) error {
	return fmt.Errorf("invalid: index table out of place, entry %d", entry.entry)
}

// archiveIndexName reports whether a name is one an archive's symbol index is
// published under: the GNU armap and its 64-bit form, and the ranlib table of a
// BSD archive, which a long name can spell as well as a header field.
func archiveIndexName(name string) bool {
	return name == "/" || name == "/SYM64/" || name == "__.SYMDEF" || name == "__.SYMDEF SORTED" || name == "__.SYMDEF_64" || name == "__.SYMDEF_64 SORTED"
}

// archiveEntries walks the headers of the archive. Nothing is decided here about
// what a header names; every entry is numbered as it stands in the file, so that
// a refusal names the entry a reader of the same bytes would count.
func archiveEntries(body []byte) ([]rawEntry, error) {
	entries := []rawEntry{}
	for position := len(archiveMagic); position < len(body); {
		entry, header := len(entries), position
		if len(body)-position < archiveHeaderLen {
			return nil, fmt.Errorf("invalid: the archive ends inside the header of entry %d", entry)
		}
		if string(body[position+58:position+archiveHeaderLen]) != "`\n" {
			return nil, fmt.Errorf("invalid: the header of entry %d is not terminated", entry)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(body[position+48:position+58])), 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("invalid: the header of entry %d states no readable size", entry)
		}
		position += archiveHeaderLen
		if int64(len(body)-position) < size {
			return nil, fmt.Errorf("invalid: entry %d extends past the end of the archive", entry)
		}
		data := body[position : position+int(size)]
		position += int(size)
		// Members stand on an even boundary. The byte that aligns them belongs
		// to no member: ar writes a newline there and go tool pack a NUL, and
		// anything else is content riding along in a byte no reader interprets.
		if size%2 == 1 {
			if position >= len(body) || (body[position] != '\n' && body[position] != 0) {
				return nil, fmt.Errorf("invalid: entry %d is not followed by the padding an odd-sized member takes", entry)
			}
			position++
		}
		// ar left-justifies the name field and pads it with spaces, so only the
		// spaces behind a name are the field's: a leading one is part of the name
		// bfd reads there.
		entries = append(entries, rawEntry{name: strings.TrimRight(string(body[header:header+16]), " "), data: data, offset: header, entry: entry})
	}

	return entries, nil
}

// archiveMemberName resolves the name an ar header spells and returns the bytes
// the member itself holds, which a BSD long name stands in front of.
func archiveMemberName(entry rawEntry, names []byte, starts map[int]bool) (string, []byte, error) {
	name, data := entry.name, entry.data
	switch {
	case strings.HasPrefix(name, "#1/"):
		length, err := strconv.Atoi(name[3:])
		if err != nil || length <= 0 || length > len(data) {
			return "", nil, fmt.Errorf("invalid: entry %d states a name length its bytes do not hold", entry.entry)
		}
		name = strings.TrimRight(string(data[:length]), "\x00")
		// A symbol index is published under a name of the header field alone. A
		// long name spelling one names no member, and reading it as the index
		// would take the table of an archive out of bytes a member holds.
		if name == "/" || name == "/SYM64/" {
			return "", nil, fmt.Errorf("invalid: entry %d spells a long name that names no member", entry.entry)
		}
		data = data[length:]
	case strings.HasPrefix(name, "/"):
		// bfd spells the offset as decimal digits and nothing else, so a sign in
		// front of one names a member ar reads nowhere.
		offset, err := strconv.ParseUint(name[1:], 10, 64)
		if err != nil || !starts[int(offset)] {
			return "", nil, fmt.Errorf("invalid: entry %d names no entry of the archive's name table", entry.entry)
		}
		name = string(names[offset : int(offset)+bytes.Index(names[offset:], []byte(archiveNameEnding))])
	default:
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" || strings.ContainsRune(name, 0) {
		return "", nil, fmt.Errorf("invalid: entry %d carries no name", entry.entry)
	}

	return name, data, nil
}

// archiveNameStarts reads the GNU name table and reports where each name it
// holds begins. The table is the names and nothing else, so a header may point
// only at a name's first byte: anything else in there is content no reader of
// this archive accounts for.
//
// bfd declares the table an even number of bytes and writes one newline behind
// the last name when the names themselves come to an odd number, so that byte
// is the table's own padding rather than content riding in it.
func archiveNameStarts(table []byte) (map[int]bool, error) {
	starts := map[int]bool{}
	for at := 0; at < len(table); {
		if at == len(table)-1 && table[at] == '\n' && len(table)%2 == 0 {
			break
		}
		end := bytes.Index(table[at:], []byte(archiveNameEnding))
		if end <= 0 || bytes.ContainsAny(table[at:at+end], archiveNameEnding) {
			return nil, fmt.Errorf("invalid: the archive's name table holds something other than the names of its members")
		}
		starts[at] = true
		at += end + len(archiveNameEnding)
	}

	return starts, nil
}

// checkArchiveIndex reads the symbol index the way a linker does: every symbol
// it publishes is an offset, and `ld -u` links whatever member stands there. An
// offset that is no member's header - one pointing into the index itself, where
// a header and an object can be hidden - would link bytes this gate never read,
// so the index must name the members and only them, and state as many symbols as
// it holds names for.
func checkArchiveIndex(index rawEntry, headers map[int]bool) error {
	// A table of no bytes carries no symbol and so points nowhere.
	if len(index.data) == 0 {
		return nil
	}
	var offsets []uint64
	var names []byte
	var err error
	switch index.name {
	case "/", "/SYM64/":
		width := 4
		if index.name == "/SYM64/" {
			width = 8
		}
		if offsets, names, err = gnuArchiveIndex(index.data, width); err != nil {
			return err
		}
		if err := checkArchiveIndexOffsets(offsets, headers); err != nil {
			return err
		}
	default:
		// A BSD ranlib table is written in the byte order of the host that
		// wrote it; which reading is the real one is settled by the offsets
		// landing on member headers.
		if offsets, names, err = ranlibArchiveIndex(index.data, index.name, headers, binary.LittleEndian); err != nil {
			if offsets, names, err = ranlibArchiveIndex(index.data, index.name, headers, binary.BigEndian); err != nil {
				return err
			}
		}
	}

	return checkArchiveIndexNames(names, len(offsets))
}

func gnuArchiveIndex(armap []byte, width int) ([]uint64, []byte, error) {
	if len(armap) < width {
		return nil, nil, shortArchiveIndex()
	}
	count := archiveIndexNumber(armap[:width], binary.BigEndian)
	if count > uint64(len(armap)-width)/uint64(width) {
		return nil, nil, shortArchiveIndex()
	}
	offsets := []uint64{}
	for n := uint64(0); n < count; n++ {
		at := width + int(n)*width
		offsets = append(offsets, archiveIndexNumber(armap[at:at+width], binary.BigEndian))
	}

	return offsets, armap[width+int(count)*width:], nil
}

// ranlibArchiveIndex reads a BSD ranlib table in the given byte order: the size
// of the symbol array in bytes, that array of (name offset, member offset)
// pairs, and the string table behind it. The offsets are checked here, because
// they are what tells one byte order from the other.
func ranlibArchiveIndex(armap []byte, kind string, headers map[int]bool, order binary.ByteOrder) ([]uint64, []byte, error) {
	width := 4
	if strings.HasPrefix(kind, "__.SYMDEF_64") {
		width = 8
	}
	if len(armap) < width {
		return nil, nil, shortArchiveIndex()
	}
	span := archiveIndexNumber(armap[:width], order)
	pair := uint64(2 * width)
	if span%pair != 0 || span > uint64(len(armap)-width) {
		return nil, nil, shortArchiveIndex()
	}
	offsets := []uint64{}
	for at := uint64(width); at < uint64(width)+span; at += pair {
		offset := archiveIndexNumber(armap[at+uint64(width):at+pair], order)
		if err := checkArchiveIndexOffsets([]uint64{offset}, headers); err != nil {
			return nil, nil, err
		}
		offsets = append(offsets, offset)
	}
	rest := armap[uint64(width)+span:]
	if len(rest) < width {
		return nil, nil, shortArchiveIndex()
	}
	size := archiveIndexNumber(rest[:width], order)
	if size > uint64(len(rest)-width) {
		return nil, nil, shortArchiveIndex()
	}

	return offsets, rest[width : uint64(width)+size], nil
}

func archiveIndexNumber(b []byte, order binary.ByteOrder) uint64 {
	if len(b) == 4 {
		return uint64(order.Uint32(b))
	}

	return order.Uint64(b)
}

func checkArchiveIndexOffsets(offsets []uint64, headers map[int]bool) error {
	for _, offset := range offsets {
		if offset > math.MaxInt64 || !headers[int(offset)] {
			return fmt.Errorf("invalid: the archive index publishes a symbol at offset %d, where no member of the archive stands", offset)
		}
	}

	return nil
}

// checkArchiveIndexNames holds the string table of the index to the symbols it
// publishes: a name for each of them and nothing else in there.
func checkArchiveIndexNames(names []byte, published int) error {
	held := 0
	for len(names) > 0 {
		end := bytes.IndexByte(names, 0)
		if end < 0 {
			return fmt.Errorf("invalid: the archive index carries bytes behind the symbol names it publishes")
		}
		if end > 0 {
			held++
		}
		names = names[end+1:]
	}
	if held != published {
		return fmt.Errorf("invalid: the archive index publishes %d symbols and holds %d names", published, held)
	}

	return nil
}

func shortArchiveIndex() error {
	return fmt.Errorf("invalid: the archive index does not hold the symbols it states")
}
