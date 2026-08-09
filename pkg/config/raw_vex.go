package config

// rawVex represents the YAML-level VEX configuration for a single image.
// The value can be either a simple string (file path) or a document reference:
//
//	image: my-app
//	dockerfile: Dockerfile
//	vex: vex/my-app.openvex.json
//
// or equivalently:
//
//	image: my-app
//	dockerfile: Dockerfile
//	vex:
//	  document: vex/my-app.openvex.json
type rawVex struct {
	doc *doc `yaml:"-"`

	// Document is a path to a VEX document file relative to the Git repository root.
	Document string `yaml:"document"`

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (v *rawVex) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try scalar string first: vex: <path>
	var s string
	if err := unmarshal(&s); err == nil {
		v.Document = s
		if v.Document == "" {
			return newDetailedConfigError("`vex` directive must specify a VEX document path, use `vex: PATH` or `vex:\n  document: PATH`", nil, v.docForErrors())
		}
		return nil
	}

	// Fall through to struct form:
	//   vex:
	//     document: <path>
	parentStack.Push(v)
	type plain rawVex
	err := unmarshal((*plain)(v))
	parentStack.Pop()
	if err != nil {
		return err
	}

	if err := checkOverflow(v.UnsupportedAttributes, nil, v.docForErrors()); err != nil {
		return err
	}

	// Validate that vex config is not empty.
	if v.Document == "" {
		return newDetailedConfigError("`vex` directive must specify a VEX document path, use `vex: PATH` or `vex:\n  document: PATH`", nil, v.docForErrors())
	}

	return nil
}

func (v *rawVex) docForErrors() *doc {
	if v != nil && v.doc != nil {
		return v.doc
	}
	return &doc{Content: []byte{}}
}

func (v *rawVex) getDoc() *doc {
	return v.doc
}
