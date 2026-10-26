package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Sign declares files of the image whose detached PKCS#7 signatures werf writes next
// to them as <file>.p7s, right after the stage named by Before or After, or at the end
// of the image when neither is set. Path is either one absolute file path or, when it
// contains `*`, an absolute glob pattern expanded against the image filesystem when the
// signing stage runs. `*` (and `**`) is the only metacharacter; every other character,
// `?`, `[` and `{` included, stands for itself.
type Sign struct {
	Path   string
	Before string
	After  string

	raw *rawSign
}

func (c *Sign) GetRaw() interface{} {
	return c.raw
}

// IsPattern reports whether Path is a glob pattern rather than one file path.
func (c *Sign) IsPattern() bool {
	return strings.Contains(c.Path, "*")
}

// Pattern is Path as a doublestar pattern: the characters doublestar would otherwise
// read as syntax are escaped, so that only `*` matches anything but itself.
func (c *Sign) Pattern() string {
	return doublestarEscaper.Replace(c.Path)
}

var doublestarEscaper = strings.NewReplacer(`\`, `\\`, `?`, `\?`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`)

// OutputPath is the signature path of a single-file entry; it is meaningless for a
// pattern, whose files are known only at signing time.
func (c *Sign) OutputPath() string {
	return SignatureOutputPath(c.Path)
}

func SignatureOutputPath(filePath string) string {
	return filePath + ".p7s"
}

// patternBase is the literal directory a pattern is expanded under; the whole image
// filesystem is too much to stream out for one signing stage.
func patternBase(pattern string) string {
	base, _ := doublestar.SplitPattern(pattern)
	return base
}

func (c *Sign) validate() error {
	switch {
	case c.Path == "":
		return newDetailedConfigError("`path: /PATH/TO/FILE` required for sign!", c.raw, c.raw.rawStapelImage.doc)
	case !path.IsAbs(c.Path) || path.Clean(c.Path) != c.Path || c.Path == "/":
		return newDetailedConfigError(fmt.Sprintf("invalid `path: %s` for sign: expected an absolute clean file path or glob pattern!", c.Path), c.raw, c.raw.rawStapelImage.doc)
	case c.IsPattern() && patternBase(c.Pattern()) == "/":
		return newDetailedConfigError(fmt.Sprintf("invalid `path: %s` for sign: a glob pattern must start with a literal directory below /!", c.Path), c.raw, c.raw.rawStapelImage.doc)
	case c.Before != "" && c.After != "":
		return newDetailedConfigError("specify only one stage using `before: install|setup` or `after: install|setup` for sign!", c.raw, c.raw.rawStapelImage.doc)
	case c.Before != "" && checkInvalidRelation(c.Before):
		return newDetailedConfigError(fmt.Sprintf("invalid stage `before: %s` for sign: expected install or setup!", c.Before), c.raw, c.raw.rawStapelImage.doc)
	case c.After != "" && checkInvalidRelation(c.After):
		return newDetailedConfigError(fmt.Sprintf("invalid stage `after: %s` for sign: expected install or setup!", c.After), c.raw, c.raw.rawStapelImage.doc)
	default:
		return nil
	}
}
