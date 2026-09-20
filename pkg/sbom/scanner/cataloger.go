package scanner

// Cataloger is a syft cataloger to enable for a scan, together with the in-image file
// paths it targets. SourcePaths are required inputs (the spec, e.g. go.mod): a directive
// scan fails if any is absent from the image. OptionalSourcePaths are best-effort inputs
// (the lock, e.g. go.sum): absent ones are skipped, matching the previous full-image scan
// which simply did not catalog a file that was not there. Enrichment, when set, names the
// installed-package files the cataloger reads next to the lock to enrich lock-derived
// components with metadata the lock lacks (licenses); it is best-effort like the lock.
// All are materialized under their full in-image path for a targeted directory scan.
type Cataloger struct {
	Name                string
	SourcePaths         []string
	OptionalSourcePaths []string
	Enrichment          *Enrichment
}

// EnrichmentKind selects how the enrichment root is copied.
type EnrichmentKind string

const (
	// EnrichmentKindDir copies the whole Root (filtered by FileNamePatterns).
	EnrichmentKindDir EnrichmentKind = "dir"
	// EnrichmentKindGoModCache copies, per module listed in the go.sum at LockPath, the
	// module's directory under Root (the Go module cache), filtered by FileNamePatterns.
	EnrichmentKindGoModCache EnrichmentKind = "go-mod-cache"
)

// Enrichment is a resolved, image-specific plan: Root is an absolute in-image directory.
type Enrichment struct {
	Kind             EnrichmentKind
	Root             string
	FileNamePatterns []string
	// LockPath is the in-image go.sum for EnrichmentKindGoModCache.
	LockPath string
}
