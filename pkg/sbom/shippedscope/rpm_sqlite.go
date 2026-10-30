package shippedscope

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// sqliteTableBlobs returns column column of every row of table, which must be a blob, read
// straight from the bytes of an SQLite database file. It knows the one thing rpm needs -
// a rowid table walked in full - and nothing of indexes, writes or the journal: rpm keeps its
// header blobs in Packages(hnum INTEGER PRIMARY KEY, blob BLOB), and nothing else is read.
//
// Any page that does not hold together is an error rather than a row skipped, because the
// caller treats a package it did not read as one the image does not have.
func sqliteTableBlobs(db []byte, table string, column int) ([][]byte, error) {
	if len(db) < 100 || string(db[:16]) != "SQLite format 3\x00" {
		return nil, errors.New("not an SQLite database")
	}
	pageSize := int(binary.BigEndian.Uint16(db[16:]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 || len(db)%pageSize != 0 {
		return nil, fmt.Errorf("SQLite page size %d does not fit a %d-byte file", pageSize, len(db))
	}
	usable := pageSize - int(db[20])
	if usable < 480 {
		return nil, errors.New("SQLite reserves too much of each page")
	}
	if binary.BigEndian.Uint32(db[56:]) > 1 {
		return nil, errors.New("SQLite text is not UTF-8")
	}
	pages := uint32(len(db) / pageSize)
	// The header's own page count is authoritative only when written by a library that
	// keeps it; then the file must hold exactly that many pages.
	if binary.BigEndian.Uint32(db[24:]) == binary.BigEndian.Uint32(db[92:]) {
		if declared := binary.BigEndian.Uint32(db[28:]); declared != pages {
			return nil, fmt.Errorf("SQLite header states %d pages, the file holds %d", declared, pages)
		}
	}
	r := sqliteReader{db: db, pageSize: pageSize, usable: usable, pages: pages}

	schema, err := r.records(1)
	if err != nil {
		return nil, err
	}
	var root uint32
	for _, record := range schema {
		values, err := sqliteRecord(record)
		if err != nil {
			return nil, err
		}
		if len(values) < 4 || values[0].text != "table" || values[1].text != table {
			continue
		}
		if root != 0 || values[3].integer <= 0 || values[3].integer > int64(pages) {
			return nil, fmt.Errorf("SQLite schema does not name one root page for %s", table)
		}
		root = uint32(values[3].integer)
	}
	if root == 0 {
		return nil, fmt.Errorf("SQLite database has no table %s", table)
	}

	rows, err := r.records(root)
	if err != nil {
		return nil, err
	}
	blobs := make([][]byte, 0, len(rows))
	for _, record := range rows {
		values, err := sqliteRecord(record)
		if err != nil {
			return nil, err
		}
		if column >= len(values) || values[column].blob == nil {
			return nil, fmt.Errorf("SQLite %s row has no blob in column %d", table, column)
		}
		blobs = append(blobs, values[column].blob)
	}

	return blobs, nil
}

type sqliteReader struct {
	db       []byte
	pageSize int
	usable   int
	pages    uint32
}

func (r sqliteReader) page(number uint32) ([]byte, int, error) {
	if number == 0 || number > r.pages {
		return nil, 0, fmt.Errorf("SQLite page %d is outside the file", number)
	}
	page := r.db[int(number-1)*r.pageSize : int(number)*r.pageSize]
	if number == 1 {
		return page, 100, nil
	}

	return page, 0, nil
}

// records walks a table b-tree from its root and returns each row's record, overflow
// joined, in rowid order.
func (r sqliteReader) records(root uint32) ([][]byte, error) {
	var out [][]byte
	visited := make(map[uint32]bool)
	var walk func(uint32) error
	walk = func(number uint32) error {
		if visited[number] {
			return fmt.Errorf("SQLite page %d is reached twice", number)
		}
		visited[number] = true
		page, start, err := r.page(number)
		if err != nil {
			return err
		}
		kind := page[start]
		header := 8
		if kind == 0x05 {
			header = 12
		} else if kind != 0x0d {
			return fmt.Errorf("SQLite page %d is not a table b-tree page", number)
		}
		cells := int(binary.BigEndian.Uint16(page[start+3:]))
		if start+header+2*cells > r.usable {
			return fmt.Errorf("SQLite page %d cell index overruns the page", number)
		}
		for i := range cells {
			offset := int(binary.BigEndian.Uint16(page[start+header+2*i:]))
			if offset < start+header+2*cells || offset >= r.usable {
				return fmt.Errorf("SQLite page %d cell %d is outside the page", number, i)
			}
			cell := page[offset:r.usable]
			if kind == 0x05 {
				if len(cell) < 4 {
					return fmt.Errorf("SQLite page %d cell %d is truncated", number, i)
				}
				if err := walk(binary.BigEndian.Uint32(cell)); err != nil {
					return err
				}

				continue
			}
			record, err := r.leafPayload(cell, visited)
			if err != nil {
				return fmt.Errorf("SQLite page %d cell %d: %w", number, i, err)
			}
			out = append(out, record)
		}
		if kind == 0x05 {
			return walk(binary.BigEndian.Uint32(page[start+8:]))
		}

		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}

	return out, nil
}

// leafPayload reads a table leaf cell's record, following its overflow chain.
func (r sqliteReader) leafPayload(cell []byte, visited map[uint32]bool) ([]byte, error) {
	size, n := sqliteVarint(cell)
	if n == 0 {
		return nil, errors.New("truncated payload size")
	}
	cell = cell[n:]
	if _, n = sqliteVarint(cell); n == 0 {
		return nil, errors.New("truncated rowid")
	}
	cell = cell[n:]
	if size > uint64(len(r.db)) {
		return nil, errors.New("payload larger than the database")
	}
	total := int(size)

	// How much of the payload stays on the leaf, as SQLite computes it.
	maxLocal := r.usable - 35
	local := total
	if total > maxLocal {
		minLocal := (r.usable-12)*32/255 - 23
		local = minLocal + (total-minLocal)%(r.usable-4)
		if local > maxLocal {
			local = minLocal
		}
	}
	if local > len(cell) || (local < total && local+4 > len(cell)) {
		return nil, errors.New("payload overruns its page")
	}
	payload := make([]byte, 0, total)
	payload = append(payload, cell[:local]...)
	if local == total {
		return payload, nil
	}
	next := binary.BigEndian.Uint32(cell[local:])
	for len(payload) < total {
		if visited[next] {
			return nil, fmt.Errorf("overflow page %d is reached twice", next)
		}
		visited[next] = true
		page, _, err := r.page(next)
		if err != nil {
			return nil, err
		}
		chunk := min(total-len(payload), r.usable-4)
		payload = append(payload, page[4:4+chunk]...)
		next = binary.BigEndian.Uint32(page)
	}
	if next != 0 {
		return nil, errors.New("overflow chain continues past the payload")
	}

	return payload, nil
}

type sqliteValue struct {
	integer int64
	text    string
	blob    []byte
}

// sqliteRecord decodes a record: integers, text and blobs. A float is never part of what
// is read here and is refused.
func sqliteRecord(record []byte) ([]sqliteValue, error) {
	headerSize, n := sqliteVarint(record)
	if n == 0 || headerSize > uint64(len(record)) || headerSize < uint64(n) {
		return nil, errors.New("SQLite record header overruns the record")
	}
	types := record[n:headerSize]
	body := record[headerSize:]
	var values []sqliteValue
	for len(types) > 0 {
		serial, n := sqliteVarint(types)
		if n == 0 {
			return nil, errors.New("SQLite record header is truncated")
		}
		types = types[n:]
		var value sqliteValue
		var width uint64
		switch {
		case serial == 0, serial == 8, serial == 9:
			value.integer = int64(serial) - 8
			if serial == 0 {
				value.integer = 0
			}
		case serial <= 6:
			width = []uint64{0, 1, 2, 3, 4, 6, 8}[serial]
		case serial >= 12:
			width = (serial - 12) / 2
		default:
			return nil, fmt.Errorf("SQLite record holds serial type %d", serial)
		}
		if width > uint64(len(body)) {
			return nil, errors.New("SQLite record value overruns the record")
		}
		raw := body[:width]
		body = body[width:]
		switch {
		case serial >= 1 && serial <= 6:
			for _, b := range raw {
				value.integer = value.integer<<8 | int64(b)
			}
			if raw[0]&0x80 != 0 {
				value.integer -= 1 << (8 * width)
			}
		case serial >= 12 && serial%2 == 0:
			// The record is a fresh copy already; the blob shares it.
			value.blob = raw[:width:width]
		case serial >= 13:
			value.text = string(raw)
		}
		values = append(values, value)
	}

	return values, nil
}

// sqliteVarint reads SQLite's big-endian varint; n is 0 when b ends inside it.
func sqliteVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}

	return 0, 0
}
