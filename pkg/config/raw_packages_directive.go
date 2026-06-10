package config

import (
	"fmt"
)

type rawPackagesDirective struct {
	Type string      `yaml:"type,omitempty"`
	Spec interface{} `yaml:"spec,omitempty"`

	rawStapelImage *rawStapelImage `yaml:"-"`

	UnsupportedAttributes map[string]interface{} `yaml:",inline"`
}

func (r *rawPackagesDirective) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if parent, ok := parentStack.Peek().(*rawStapelImage); ok {
		r.rawStapelImage = parent
	}

	parentStack.Push(r)
	type plain rawPackagesDirective
	err := unmarshal((*plain)(r))
	parentStack.Pop()
	if err != nil {
		return err
	}

	if err := checkOverflow(r.UnsupportedAttributes, nil, r.docForErrors()); err != nil {
		return err
	}

	if r.Type == "" {
		return newDetailedConfigError("the `type` is required for each packages directive entry!", nil, r.docForErrors())
	}

	if r.Spec == nil {
		return newDetailedConfigError("the `spec` is required for each packages directive entry!", nil, r.docForErrors())
	}

	return nil
}

func (r *rawPackagesDirective) docForErrors() *doc {
	if r.rawStapelImage != nil {
		return r.rawStapelImage.doc
	}
	return &doc{Content: []byte{}}
}

func (r *rawPackagesDirective) toDirective() (*PackagesDirective, error) {
	d := &PackagesDirective{
		Type: PackagesDirectiveType(r.Type),
	}

	switch v := r.Spec.(type) {
	case string:
		d.Spec.FilePath = v
	case []interface{}:
		packages, err := InterfaceToStringArray(v, nil, r.rawStapelImage.doc)
		if err != nil {
			return nil, err
		}
		d.Spec.Packages = packages
	default:
		return nil, fmt.Errorf("unsupported packages spec type %T for type %q", r.Spec, r.Type)
	}

	if err := d.validate(); err != nil {
		return nil, err
	}

	return d, nil
}
