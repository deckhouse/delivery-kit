package shippedscope

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	bdbHashMagic     = 0x061561
	bdbPageHashMeta  = 8
	bdbPageHash      = 13
	bdbPageHashOld   = 2
	bdbPageOverflow  = 7
	bdbItemKeyData   = 1
	bdbItemOffPage   = 3
	bdbPageHeader    = 26
	bdbMetaChecksum  = 0x01
	bdbOffPageLength = 12
)

// bdbHashValues returns every value of a Berkeley DB hash database, read straight from the
// bytes of its file: the form rpm kept Packages in before SQLite, keyed by header number.
// Pages are read in file order; a database written with checksums or encryption, holding
// duplicate keys, or not holding together is an error rather than a value skipped, since
// the caller takes a package it did not read for one the image does not have.
func bdbHashValues(db []byte) (map[uint32][]byte, error) {
	if len(db) < 512 {
		return nil, errors.New("not a Berkeley DB hash database")
	}
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint32(db[12:]) != bdbHashMagic {
		order = binary.BigEndian
		if order.Uint32(db[12:]) != bdbHashMagic {
			return nil, errors.New("not a Berkeley DB hash database")
		}
	}
	pageSize := int(order.Uint32(db[20:]))
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("Berkeley DB page size %d", pageSize)
	}
	if db[24] != 0 || db[26]&bdbMetaChecksum != 0 {
		return nil, errors.New("Berkeley DB is encrypted or checksummed")
	}
	if db[25] != bdbPageHashMeta {
		return nil, errors.New("Berkeley DB does not start with hash metadata")
	}
	last := uint64(order.Uint32(db[32:]))
	if (last+1)*uint64(pageSize) > uint64(len(db)) {
		return nil, fmt.Errorf("Berkeley DB states %d pages, the file holds fewer", last+1)
	}
	page := func(number uint32) ([]byte, error) {
		if number == 0 || uint64(number) > last {
			return nil, fmt.Errorf("Berkeley DB page %d is outside the file", number)
		}

		return db[int(number)*pageSize : int(number+1)*pageSize], nil
	}

	values := make(map[uint32][]byte)
	for number := uint32(1); uint64(number) <= last; number++ {
		p, _ := page(number)
		if p[25] != bdbPageHash && p[25] != bdbPageHashOld {
			continue
		}
		entries := int(order.Uint16(p[20:]))
		if entries%2 != 0 || bdbPageHeader+2*entries > pageSize {
			return nil, fmt.Errorf("Berkeley DB page %d has a broken item index", number)
		}
		item := func(i int) ([]byte, error) {
			start := int(order.Uint16(p[bdbPageHeader+2*i:]))
			end := pageSize
			if i > 0 {
				end = int(order.Uint16(p[bdbPageHeader+2*(i-1):]))
			}
			if start < bdbPageHeader+2*entries || start >= end || end > pageSize {
				return nil, fmt.Errorf("Berkeley DB page %d item %d is outside the page", number, i)
			}

			return p[start:end], nil
		}
		for i := 0; i < entries; i += 2 {
			key, err := item(i)
			if err != nil {
				return nil, err
			}
			value, err := item(i + 1)
			if err != nil {
				return nil, err
			}
			if key[0] != bdbItemKeyData || len(key) != 5 {
				return nil, fmt.Errorf("Berkeley DB page %d holds a key that is not a header number", number)
			}
			var data []byte
			switch value[0] {
			case bdbItemKeyData:
				data = value[1:]
			case bdbItemOffPage:
				if len(value) < bdbOffPageLength {
					return nil, fmt.Errorf("Berkeley DB page %d holds a truncated off-page item", number)
				}
				if data, err = bdbOverflow(order, page, order.Uint32(value[4:]), order.Uint32(value[8:])); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("Berkeley DB page %d holds item type %d", number, value[0])
			}
			// rpm keys headers by their number in the host's byte order; record 0
			// holds the next number to hand out, not a header.
			instance := order.Uint32(key[1:])
			if instance == 0 {
				continue
			}
			if _, seen := values[instance]; seen {
				return nil, fmt.Errorf("Berkeley DB holds header %d twice", instance)
			}
			values[instance] = data
		}
	}

	return values, nil
}

// bdbOverflow joins the chain of overflow pages an off-page item points at.
func bdbOverflow(order binary.ByteOrder, page func(uint32) ([]byte, error), first, length uint32) ([]byte, error) {
	data := make([]byte, 0, min(length, 1<<24))
	visited := make(map[uint32]bool)
	for next := first; next != 0; {
		if visited[next] {
			return nil, fmt.Errorf("Berkeley DB overflow page %d is reached twice", next)
		}
		visited[next] = true
		p, err := page(next)
		if err != nil {
			return nil, err
		}
		used := int(order.Uint16(p[22:]))
		if p[25] != bdbPageOverflow || bdbPageHeader+used > len(p) {
			return nil, fmt.Errorf("Berkeley DB page %d is not an overflow page", next)
		}
		data = append(data, p[bdbPageHeader:bdbPageHeader+used]...)
		next = order.Uint32(p[16:])
	}
	if uint32(len(data)) != length {
		return nil, fmt.Errorf("Berkeley DB overflow chain holds %d bytes, the item states %d", len(data), length)
	}

	return data, nil
}
