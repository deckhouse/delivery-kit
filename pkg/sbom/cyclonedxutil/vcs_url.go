package cyclonedxutil

import (
	"regexp"
	"strings"
)

var scpLikeURL = regexp.MustCompile(`^([A-Za-z0-9._-]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):(?:/)?([^/].*)$`)

// VCSURL turns a repository address into a URL CycloneDX accepts as an IRI reference.
// Package metadata often names a repository the way git clone takes it —
// "git@github.com:org/repo.git" — which is not a URL at all; it is rewritten to
// the ssh:// form. Anything with a scheme is returned unchanged.
func VCSURL(address string) string {
	address = strings.TrimSpace(address)
	if address == "" || strings.Contains(address, "://") {
		return address
	}
	m := scpLikeURL.FindStringSubmatch(address)
	if m == nil {
		return address
	}
	return "ssh://" + m[1] + m[2] + "/" + m[3]
}
