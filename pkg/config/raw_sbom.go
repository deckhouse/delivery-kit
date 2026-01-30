package config

type rawSbom struct {
	Use bool `yaml:"use,omitempty"`

	rawMetaBuild *rawMetaBuild `yaml:"-"`

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (s *rawSbom) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if parent, ok := parentStack.Peek().(*rawMetaBuild); ok {
		s.rawMetaBuild = parent
	}

	parentStack.Push(s)
	type plain rawSbom
	err := unmarshal((*plain)(s))
	parentStack.Pop()
	if err != nil {
		return err
	}

	if err := checkOverflow(s.UnsupportedAttributes, nil, s.rawMetaBuild.rawMeta.doc); err != nil {
		return err
	}

	return nil
}

func (s *rawSbom) toDirective() *Sbom {
	return &Sbom{
		Use: s.Use,
	}
}
