// Portions of this file are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/internal/cpegenerate/vendors_from_url.go
// and https://github.com/anchore/syft/blob/main/internal/regex_helpers.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

import (
	"regexp"
	"strings"
)

// urlPrefixToVendor maps a well-known project URL prefix to its canonical
// NVD vendor. The list is intentionally conservative: only prefixes for which
// the vendor is unambiguous across every project hosted at that URL are
// included. Prefixes derived from Anchore syft; entries under pm-specific
// hosts (savannah, kernel.org, netfilter, gnupg, sourceware git paths) are
// added to cover the delivery-kit pm-index host distribution.
var urlPrefixToVendor = map[string]string{
	// Anchore syft originals
	"https://www.gnu.org/":         "gnu",
	"https://developer.gnome.org/": "gnome",
	"https://gitlab.gnome.org/":    "gnome",
	"https://jqlang.github.io/":    "jqlang",
	"https://www.ruby-lang.org/":   "ruby-lang",
	"https://llvm.org/":            "llvm",
	"https://www.isc.org/":         "isc",
	"https://musl.libc.org/":       "musl-libc",
	"https://www.mozilla.org/":     "mozilla",
	"https://www.openssl.org/":     "openssl",
	"https://www.x.org/":           "x.org",
	"https://w1.fi/":               "w1.fi",
	"https://zlib.net/":            "zlib",

	// pm-index additions: GNU family
	"https://gcc.gnu.org/":               "gnu",
	"https://git.savannah.gnu.org/":      "gnu",
	"https://cgit.git.savannah.gnu.org/": "gnu",
	"https://savannah.nongnu.org/":       "gnu",

	// pm-index additions: kernel / netfilter / gnupg
	"https://git.kernel.org/":    "kernel",
	"git://git.kernel.org/":      "kernel",
	"https://git.netfilter.org/": "netfilter",
	"https://www.netfilter.org/": "netfilter",
	"https://git.gnupg.org/":     "gnupg",
	"https://www.gnupg.org/":     "gnupg",
}

// vendorExtractionPatterns pulls a vendor slug out of a hosted-git URL. The
// github.com/gitlab.com pattern is copied verbatim from Anchore syft; the
// self-hosted gitlab pattern is a delivery-kit addition to cover
// gitlab.freedesktop.org, gitlab.gnome.org, gitlab.inria.fr etc. that appear
// in the pm-index.
var vendorExtractionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:https|http|git)://(?:github|gitlab)\.com/(?P<vendor>[\w\-]+)/.*$`),
	regexp.MustCompile(`^(?:https|http|git)://gitlab\.[\w.\-]+/(?P<vendor>[\w\-]+)/.*$`),
}

// candidateVendorsFromURL returns zero or more CPE vendor candidates inferred
// from a project URL. Hard-coded prefix hits take precedence over regex
// extraction, and only the first successful strategy contributes candidates.
// Callers must treat the result as a hint; final CPEs still need validation.
func candidateVendorsFromURL(url string) []string {
	if url == "" {
		return nil
	}

	for prefix, vendor := range urlPrefixToVendor {
		if strings.HasPrefix(url, prefix) {
			return []string{vendor}
		}
	}

	for _, p := range vendorExtractionPatterns {
		if groups := matchNamedCaptureGroups(p, url); groups != nil {
			if v := groups["vendor"]; v != "" {
				return []string{v}
			}
		}
	}

	return nil
}

// matchNamedCaptureGroups returns the named capture groups from the first
// non-empty match of re against content. Copied from
// Anchore syft's internal.MatchNamedCaptureGroups helper because the syft
// internal/ package cannot be imported by external modules.
func matchNamedCaptureGroups(re *regexp.Regexp, content string) map[string]string {
	allMatches := re.FindAllStringSubmatch(content, -1)
	var results map[string]string
	for _, match := range allMatches {
		for nameIdx, name := range re.SubexpNames() {
			if nameIdx > len(match) || name == "" {
				continue
			}
			if results == nil {
				results = make(map[string]string)
			}
			results[name] = match[nameIdx]
		}
		if !isEmptyMap(results) {
			break
		}
	}
	return results
}

func isEmptyMap(m map[string]string) bool {
	for _, v := range m {
		if v != "" {
			return false
		}
	}
	return true
}
