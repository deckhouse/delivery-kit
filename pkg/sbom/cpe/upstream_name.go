// Portions of this file are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/internal/cpegenerate/apk.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

import (
	"regexp"
	"strings"
)

var (
	streamVersionPkgNamePattern = regexp.MustCompile(`^(?P<stream>[a-zA-Z][\w-]*?)(?P<streamVersion>\-?\d[\d\.]*?)($|-(?P<subPackage>[a-zA-Z][\w-]*?)?)$`)
	developmentSuffixes         = []string{"-devel", "-libs", "-dev"}
)

func normalizePackageName(name string) string {
	if name == "" {
		return ""
	}

	stripped := stripDevelopmentSuffix(name)
	groups := matchNamedCaptureGroups(streamVersionPkgNamePattern, stripped)
	stream := groups["stream"]
	if stream == "" {
		return stripped
	}

	subPackage := groups["subPackage"]
	if subPackage != "" {
		return stream + "-" + subPackage
	}

	return stream
}

func stripDevelopmentSuffix(name string) string {
	for _, suffix := range developmentSuffixes {
		if strings.HasSuffix(name, suffix) && len(name) > len(suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}

	return name
}
