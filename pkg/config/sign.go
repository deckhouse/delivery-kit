package config

import (
	"fmt"
	"path"
)

// Sign declares a file of the image whose detached PKCS#7 signature werf writes
// next to it as <Path>.p7s, right after the stage named by Before or After, or at
// the end of the image when neither is set.
type Sign struct {
	Path   string
	Before string
	After  string

	raw *rawSign
}

func (c *Sign) GetRaw() interface{} {
	return c.raw
}

func (c *Sign) OutputPath() string {
	return c.Path + ".p7s"
}

func (c *Sign) validate() error {
	switch {
	case c.Path == "":
		return newDetailedConfigError("`path: /PATH/TO/FILE` required for sign!", c.raw, c.raw.rawStapelImage.doc)
	case !path.IsAbs(c.Path) || path.Clean(c.Path) != c.Path || c.Path == "/":
		return newDetailedConfigError(fmt.Sprintf("invalid `path: %s` for sign: expected an absolute clean file path!", c.Path), c.raw, c.raw.rawStapelImage.doc)
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
