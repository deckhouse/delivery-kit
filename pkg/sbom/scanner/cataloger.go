package scanner

// Cataloger is a syft cataloger to enable for a scan, together with the in-image
// file paths it targets (e.g. go.mod / go.sum), which are materialized under their
// full in-image path for a targeted directory scan.
type Cataloger struct {
	Name        string
	SourcePaths []string
}
