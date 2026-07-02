package config

import "fmt"

type rawPackagesDirective struct {
	Type    string      `yaml:"type,omitempty"`
	Spec    interface{} `yaml:"spec,omitempty"`
	Workdir string      `yaml:"workdir,omitempty"`
	Lock    string      `yaml:"lock,omitempty"`

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

	if PackagesDirectiveType(r.Type) == PackagesDirectiveTypeOSPM && r.Spec == nil {
		return newDetailedConfigError("the `spec` is required for `os-pm` packages directive entry!", nil, r.docForErrors())
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
	if canonical, ok := aliasToType[r.Type]; ok {
		r.Type = string(canonical)
	}

	d := &PackagesDirective{
		Type: PackagesDirectiveType(r.Type),
	}

	if d.Type == PackagesDirectiveTypeOSPM {
		if err := r.fillOSPMSpec(d); err != nil {
			return nil, err
		}
	} else if _, ok := ecosystems[d.Type]; ok {
		if err := r.fillFileBasedSpec(d); err != nil {
			return nil, err
		}
	}

	if err := d.validate(); err != nil {
		return nil, err
	}

	return d, nil
}

func (r *rawPackagesDirective) fillOSPMSpec(d *PackagesDirective) error {
	switch v := r.Spec.(type) {
	case []interface{}:
		packages, err := InterfaceToStringArray(v, nil, r.rawStapelImage.doc)
		if err != nil {
			return err
		}
		d.Spec.Packages = packages
	default:
		return fmt.Errorf("unsupported packages spec type %T for type %q; spec must be a list of package names", r.Spec, r.Type)
	}

	return nil
}

func (r *rawPackagesDirective) fillFileBasedSpec(d *PackagesDirective) error {
	eco := ecosystems[d.Type]

	d.FileBased.Workdir = r.Workdir

	d.FileBased.Spec = eco.DefaultSpec
	if r.Spec != nil {
		spec, ok := r.Spec.(string)
		if !ok {
			return fmt.Errorf("spec must be a string for type %q", d.Type)
		}
		if spec != "" {
			d.FileBased.Spec = spec
		}
	}

	d.FileBased.Lock = eco.DefaultLock
	if r.Lock != "" {
		d.FileBased.Lock = r.Lock
	}

	return nil
}
