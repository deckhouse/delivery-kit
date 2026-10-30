//go:build embedwebpack

package webpackcollector

import (
	_ "embed"
)

//go:embed embed/collector.tar.gz
var embeddedCollector []byte

//go:embed embed/collector.tar.sha256
var embeddedCollectorSha256 string

func embeddedArchive() ([]byte, string, bool) {
	return embeddedCollector, embeddedCollectorSha256, true
}
