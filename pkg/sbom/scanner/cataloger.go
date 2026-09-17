package scanner

// Cataloger is a syft cataloger to enable for a scan, together with the in-image file
// paths it targets. SourcePaths are required inputs (the spec, e.g. go.mod): a directive
// scan fails if any is absent from the image. OptionalSourcePaths are best-effort inputs
// (the lock, e.g. go.sum): absent ones are skipped, matching the previous full-image scan
// which simply did not catalog a file that was not there. All are materialized under their
// full in-image path for a targeted directory scan.
type Cataloger struct {
	Name                string
	SourcePaths         []string
	OptionalSourcePaths []string
}
