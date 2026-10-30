//go:build !embedwebpack

package webpackcollector

// embeddedArchive reports that this build carries no collector, so a stage that needs
// one is refused rather than built without the evidence it was declared to produce.
func embeddedArchive() ([]byte, string, bool) {
	return nil, "", false
}
