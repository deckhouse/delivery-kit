// Portions of this file are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/internal/cpegenerate/generate.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"unicode"
)

var trailingDigits = regexp.MustCompile(`\d+$`)

// withDelimiterVariations returns the input values plus hyphen<->underscore
// swapped variants for any value containing '-' or '_'. NVD frequently records
// a product/vendor with the opposite delimiter to the package name, so emitting
// both forms improves CVE match recall.
func withDelimiterVariations(values []string) []string {
	result := append([]string(nil), values...)
	for _, v := range values {
		if strings.Contains(v, "-") {
			result = append(result, strings.ReplaceAll(v, "-", "_"))
		}
		if strings.Contains(v, "_") {
			result = append(result, strings.ReplaceAll(v, "_", "-"))
		}
	}
	return result
}

// withSubSelections returns the input values plus progressive sub-selections
// split on hyphen/underscore (e.g. "jenkins-ci" -> "jenkins", "jenkins-ci").
func withSubSelections(values []string) []string {
	result := append([]string(nil), values...)
	for _, v := range values {
		result = append(result, generateSubSelections(v)...)
	}
	return result
}

// withDigitVariations returns the input values plus, for any value ending in a
// digit, the value with all trailing digits removed (e.g. "qt5" -> "qt").
func withDigitVariations(values []string) []string {
	result := append([]string(nil), values...)
	for _, v := range values {
		if !endsWithNumber(v) {
			continue
		}
		if stripped := trailingDigits.ReplaceAllString(v, ""); stripped != "" && stripped != v {
			result = append(result, stripped)
		}
	}
	return result
}

func endsWithNumber(s string) bool {
	if s == "" {
		return false
	}
	r := []rune(s)
	return unicode.IsDigit(r[len(r)-1])
}

func generateSubSelections(field string) (results []string) {
	scanner := bufio.NewScanner(strings.NewReader(field))
	scanner.Split(scanByHyphenOrUnderscore)
	var lastToken byte
	for scanner.Scan() {
		rawCandidate := scanner.Text()
		if len(rawCandidate) == 0 {
			break
		}

		candidate := strings.TrimFunc(rawCandidate, trimHyphenOrUnderscore)
		if len(candidate) > 0 {
			if len(results) > 0 {
				results = append(results, results[len(results)-1]+string(lastToken)+candidate)
			} else {
				results = append(results, candidate)
			}
		}

		lastToken = rawCandidate[len(rawCandidate)-1]
	}
	return results
}

func scanByHyphenOrUnderscore(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "-_"); i >= 0 {
		return i + 1, data[0 : i+1], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func trimHyphenOrUnderscore(r rune) bool {
	return r == '-' || r == '_'
}
