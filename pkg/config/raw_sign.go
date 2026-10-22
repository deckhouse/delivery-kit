package config

type rawSign struct {
	Path   string `yaml:"path,omitempty"`
	Before string `yaml:"before,omitempty"`
	After  string `yaml:"after,omitempty"`

	rawStapelImage *rawStapelImage `yaml:"-"` // parent

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (c *rawSign) configSection() interface{} {
	return c
}

func (c *rawSign) doc() *doc {
	return c.rawStapelImage.doc
}

func (c *rawSign) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if parent, ok := parentStack.Peek().(*rawStapelImage); ok {
		c.rawStapelImage = parent
	}

	parentStack.Push(c)
	type plain rawSign
	err := unmarshal((*plain)(c))
	parentStack.Pop()
	if err != nil {
		return err
	}

	return checkOverflow(c.UnsupportedAttributes, c, c.rawStapelImage.doc)
}

func (c *rawSign) toDirective() (*Sign, error) {
	sign := &Sign{
		Path:   c.Path,
		Before: c.Before,
		After:  c.After,
		raw:    c,
	}

	if err := sign.validate(); err != nil {
		return nil, err
	}

	return sign, nil
}
