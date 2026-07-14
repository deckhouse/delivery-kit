package scanner

// CatalogerFilterMode controls how BOM components are matched back to a cataloger's scope.
type CatalogerFilterMode int

const (
	CatalogerFilterExactPath     CatalogerFilterMode = iota
	CatalogerFilterWorkdirPrefix CatalogerFilterMode = iota
	CatalogerFilterCatalogerOnly CatalogerFilterMode = iota
)

// Cataloger is a syft cataloger to enable for a scan, together with the in-image
// file paths it targets (e.g. go.mod / go.sum) and the filter mode that controls
// how BOM components are matched back to this cataloger's scope.
type Cataloger struct {
	Name        string
	FilterMode  CatalogerFilterMode
	SourcePaths []string
	Workdir     string
}
