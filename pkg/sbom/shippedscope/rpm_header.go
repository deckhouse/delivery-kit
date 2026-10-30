package shippedscope

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// rpmPackage is what one installed package's header says about itself: its identity and
// the paths rpm recorded for it.
type rpmPackage struct {
	Name    string
	Version string
	Release string
	Arch    string
	Epoch   int32
	Files   []string
}

// EVR spells the version the way rpm compares it: the epoch only when there is one, since a
// package built without an epoch and one built with epoch 0 are the same build.
func (p rpmPackage) EVR() string {
	if p.Epoch == 0 {
		return p.Version + "-" + p.Release
	}

	return strconv.Itoa(int(p.Epoch)) + ":" + p.Version + "-" + p.Release
}

const (
	rpmTagName        = 1000
	rpmTagVersion     = 1001
	rpmTagRelease     = 1002
	rpmTagEpoch       = 1003
	rpmTagArch        = 1022
	rpmTagOldFiles    = 1027
	rpmTagDirIndexes  = 1116
	rpmTagBasenames   = 1117
	rpmTagDirnames    = 1118
	rpmTypeInt32      = 4
	rpmTypeString     = 6
	rpmTypeStringList = 8
	rpmTypeI18N       = 9
	// Bounds rpm itself puts on a header it will load.
	rpmMaxIndexEntries = 0xffff
	rpmMaxDataLength   = 0x0fffffff
)

// parseRPMHeader reads a header blob as both rpm databases keep it: the tag index and the
// data store, without the magic a package file puts in front. Anything that does not hold
// together is an error; the caller then reads nothing of the database at all, since a
// package skipped here would be taken for one the image does not have.
func parseRPMHeader(blob []byte) (rpmPackage, error) {
	if len(blob) < 8 {
		return rpmPackage{}, errors.New("rpm header shorter than its preamble")
	}
	entries, dataLength := binary.BigEndian.Uint32(blob), binary.BigEndian.Uint32(blob[4:])
	if entries == 0 || entries > rpmMaxIndexEntries || dataLength > rpmMaxDataLength {
		return rpmPackage{}, fmt.Errorf("rpm header claims %d tags and %d bytes", entries, dataLength)
	}
	storeStart := 8 + 16*uint64(entries)
	if storeStart+uint64(dataLength) > uint64(len(blob)) {
		return rpmPackage{}, errors.New("rpm header is truncated")
	}
	store := blob[storeStart : storeStart+uint64(dataLength)]

	type entry struct{ typ, offset, count uint32 }
	tags := make(map[uint32]entry, 9)
	for i := uint64(0); i < uint64(entries); i++ {
		raw := blob[8+16*i:]
		tag := binary.BigEndian.Uint32(raw)
		switch tag {
		case rpmTagName, rpmTagVersion, rpmTagRelease, rpmTagEpoch, rpmTagArch,
			rpmTagOldFiles, rpmTagDirIndexes, rpmTagBasenames, rpmTagDirnames:
		default:
			continue
		}
		if _, seen := tags[tag]; seen {
			return rpmPackage{}, fmt.Errorf("rpm header states tag %d twice", tag)
		}
		e := entry{binary.BigEndian.Uint32(raw[4:]), binary.BigEndian.Uint32(raw[8:]), binary.BigEndian.Uint32(raw[12:])}
		if e.offset >= uint32(len(store)) {
			return rpmPackage{}, fmt.Errorf("rpm header tag %d points past its data", tag)
		}
		tags[tag] = e
	}

	str := func(tag uint32) (string, bool, error) {
		e, ok := tags[tag]
		if !ok {
			return "", false, nil
		}
		if e.typ != rpmTypeString && e.typ != rpmTypeI18N {
			return "", false, fmt.Errorf("rpm header tag %d is not a string", tag)
		}
		values, err := rpmStrings(store[e.offset:], 1)
		if err != nil {
			return "", false, err
		}

		return values[0], true, nil
	}
	list := func(tag uint32) ([]string, error) {
		e, ok := tags[tag]
		if !ok {
			return nil, nil
		}
		if e.typ != rpmTypeStringList {
			return nil, fmt.Errorf("rpm header tag %d is not a string list", tag)
		}

		return rpmStrings(store[e.offset:], e.count)
	}
	ints := func(tag uint32) ([]int32, bool, error) {
		e, ok := tags[tag]
		if !ok {
			return nil, false, nil
		}
		if e.typ != rpmTypeInt32 || uint64(e.offset)+4*uint64(e.count) > uint64(len(store)) {
			return nil, false, fmt.Errorf("rpm header tag %d is not an int32 array inside its data", tag)
		}
		values := make([]int32, e.count)
		for i := range values {
			values[i] = int32(binary.BigEndian.Uint32(store[e.offset+4*uint32(i):]))
		}

		return values, true, nil
	}

	var pkg rpmPackage
	var err error
	var ok bool
	for tag, target := range map[uint32]*string{rpmTagName: &pkg.Name, rpmTagVersion: &pkg.Version, rpmTagRelease: &pkg.Release} {
		if *target, ok, err = str(tag); err != nil {
			return rpmPackage{}, err
		} else if !ok || *target == "" {
			return rpmPackage{}, fmt.Errorf("rpm header has no tag %d", tag)
		}
	}
	// gpg-pubkey and the like carry no architecture.
	if pkg.Arch, _, err = str(rpmTagArch); err != nil {
		return rpmPackage{}, err
	}
	epoch, hasEpoch, err := ints(rpmTagEpoch)
	if err != nil {
		return rpmPackage{}, err
	}
	if hasEpoch {
		if len(epoch) != 1 {
			return rpmPackage{}, errors.New("rpm header states more than one epoch")
		}
		pkg.Epoch = epoch[0]
	}

	basenames, err := list(rpmTagBasenames)
	if err != nil {
		return rpmPackage{}, err
	}
	dirnames, err := list(rpmTagDirnames)
	if err != nil {
		return rpmPackage{}, err
	}
	indexes, _, err := ints(rpmTagDirIndexes)
	if err != nil {
		return rpmPackage{}, err
	}
	if len(basenames) != len(indexes) {
		return rpmPackage{}, errors.New("rpm header file names and their directories disagree")
	}
	for i, base := range basenames {
		if indexes[i] < 0 || int(indexes[i]) >= len(dirnames) {
			return rpmPackage{}, errors.New("rpm header file names a directory it does not list")
		}
		pkg.Files = append(pkg.Files, dirnames[indexes[i]]+base)
	}
	if len(basenames) == 0 {
		// Headers older than compressed file lists keep whole paths.
		if pkg.Files, err = list(rpmTagOldFiles); err != nil {
			return rpmPackage{}, err
		}
	}

	return pkg, nil
}

// rpmStrings reads count NUL-terminated strings from the start of data.
func rpmStrings(data []byte, count uint32) ([]string, error) {
	values := make([]string, 0, min(count, 1024))
	for range count {
		end := 0
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end == len(data) {
			return nil, errors.New("rpm header string runs past its data")
		}
		values = append(values, string(data[:end]))
		data = data[end+1:]
	}

	return values, nil
}
