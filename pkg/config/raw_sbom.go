package config

type rawSbom struct {
	doc *doc `yaml:"-"`

	Gost *rawGost `yaml:"gost,omitempty"`

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (s *rawSbom) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Bind to parent context for proper error reporting.
	// rawSbom can appear only under image sections (parent: *rawStapelImage or *rawImageFromDockerfile).
	switch parent := parentStack.Peek().(type) {
	case *rawStapelImage:
		s.doc = parent.doc
	case *rawImageFromDockerfile:
		s.doc = parent.doc
	case *rawSbom:
		// In case of nested parsing (shouldn't normally happen), inherit context.
		s.doc = parent.doc
	}

	parentStack.Push(s)
	type plain rawSbom
	err := unmarshal((*plain)(s))
	parentStack.Pop()
	if err != nil {
		return err
	}

	if err := checkOverflow(s.UnsupportedAttributes, nil, s.docForErrors()); err != nil {
		return err
	}

	return nil
}

func (s *rawSbom) docForErrors() *doc {
	if s != nil && s.doc != nil {
		return s.doc
	}
	// Fallback: avoid panics in error formatting in unexpected edge cases.
	return &doc{Content: []byte{}}
}
