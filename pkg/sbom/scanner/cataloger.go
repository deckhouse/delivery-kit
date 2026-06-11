package scanner

// Cataloger is a syft cataloger to enable for a scan, together with the in-image
// file paths it targets (e.g. go.mod / go.sum).
type Cataloger struct {
	Name        string
	SourcePaths []string
}
