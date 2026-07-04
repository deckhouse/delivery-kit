// Portions of this file are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/internal/cpegenerate/candidate_by_package_type.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

// additionalVendorsByPackage are curated vendor hints ported from syft for
// the system-package / binary-package cases relevant to pm-managed components.
// They are keyed by normalized package name after stripping development
// suffixes.
var additionalVendorsByPackage = map[string][]string{
	"alsa":                   {"alsa-project"},
	"alsa-lib":               {"alsa-project"},
	"bash":                   {"gnu"},
	"bazel":                  {"google"},
	"bind":                   {"isc"},
	"clang":                  {"llvm"},
	"composer":               {"getcomposer"},
	"consule":                {"hashicorp"},
	"curl":                   {"haxx"},
	"dnsmasq":                {"thekelleys"},
	"firefox":                {"mozilla"},
	"firefox-esr":            {"mozilla"},
	"fluent-bit":             {"treasuredata"},
	"gcc":                    {"gnu"},
	"ghostscript":            {"artifex"},
	"git":                    {"git-scm"},
	"glib":                   {"gnome"},
	"glibc":                  {"gnu"},
	"go":                     {"golang"},
	"httpd":                  {"apache"},
	"julia":                  {"julialang"},
	"libavif":                {"aomedia"},
	"libxpm":                 {"libxpm_project"},
	"make":                   {"gnu"},
	"musl":                   {"musl-libc"},
	"mysql":                  {"oracle"},
	"nginx":                  {"f5"},
	"node":                   {"nodejs"},
	"openjdk":                {"oracle"},
	"openjpeg":               {"uclouvain"},
	"percona-server":         {"oracle", "percona"},
	"percona-xtradb-cluster": {"oracle", "percona"},
	"percona-xtrabackup":     {"percona"},
	"php":                    {"php"},
	"php-cli":                {"php"},
	"php-fpm":                {"php"},
	"podofo":                 {"podofo_project"},
	"python":                 {"python_software_foundation"},
	"python3":                {"python", "python_software_foundation"},
	"redis":                  {"redislabs"},
	"ruby":                   {"ruby-lang"},
	"rust":                   {"rust-lang"},
	"swipl":                  {"erlang"},
	"thunderbird":            {"mozilla"},
	"util-linux":             {"kernel"},
	"wpa_supplicant":         {"w1.fi"},
	"xorg-server":            {"x.org"},
}

// additionalProductsByPackage are curated product hints ported from syft for
// the pm-relevant package classes.
var additionalProductsByPackage = map[string][]string{
	"apache":                 {"http_server"},
	"chromium":               {"chrome"},
	"erlang":                 {"erlang/otp"},
	"fluent-bit":             {"fluent_bit"},
	"httpd":                  {"http_server"},
	"libphp":                 {"php"},
	"node":                   {"node.js", "nodejs"},
	"nodejs":                 {"node.js"},
	"nodejs-current":         {"node.js"},
	"percona-server":         {"percona_server", "mysql"},
	"percona-xtradb-cluster": {"percona_server", "mysql", "xtradb_cluster"},
	"percona-xtrabackup":     {"xtrabackup"},
	"php-cli":                {"php"},
	"php-fpm":                {"php"},
	"swipl":                  {"erlang/otp"},
	"tiff":                   {"libtiff"},
	"xorg-server":            {"x_server"},
}
