package config

type rawMetaBuildSbom struct {
	Enable bool `yaml:"enable,omitempty"`

	rawMetaBuild *rawMetaBuild `yaml:"-"`

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (s *rawMetaBuildSbom) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if parent, ok := parentStack.Peek().(*rawMetaBuild); ok {
		s.rawMetaBuild = parent
	}

	parentStack.Push(s)
	type plain rawMetaBuildSbom
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

func (s *rawMetaBuildSbom) toDirective() *MetaBuildSbom {
	if s == nil {
		return nil
	}

	return &MetaBuildSbom{
		Enable: s.Enable,
	}
}
