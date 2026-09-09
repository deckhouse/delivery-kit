package scanner

// Cataloger is a syft cataloger to enable for a scan, together with the in-image
// file paths it targets (e.g. go.mod / go.sum) and the workdir those paths are
// declared under, used to materialize them for a targeted directory scan.
type Cataloger struct {
	Name        string
	SourcePaths []string
	Workdir     string
}
