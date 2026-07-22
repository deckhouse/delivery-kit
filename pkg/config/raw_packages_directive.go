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

	if err := r.fillFileBasedSpec(d); err != nil {
		return nil, err
	}

	if err := d.validate(); err != nil {
		return nil, err
	}

	return d, nil
}

func (r *rawPackagesDirective) fillFileBasedSpec(d *PackagesDirective) error {
	eco, ok := ecosystems[d.Type]
	if !ok {
		return fmt.Errorf("unsupported packages type %q", d.Type)
	}

	if d.Type == PackagesDirectiveTypeOSPM {
		rawPkgs, ok := r.Spec.([]interface{})
		if !ok {
			return fmt.Errorf("unsupported packages spec type %T for type %q; spec must be a list of package names", r.Spec, d.Type)
		}
		pkgs := make([]string, len(rawPkgs))
		for i, v := range rawPkgs {
			pkgs[i] = fmt.Sprint(v)
		}
		d.Spec.Packages = pkgs
		return nil
	}

	d.FileBased.Workdir = r.Workdir

	d.FileBased.Spec = eco.DefaultSpecFile
	if r.Spec != nil {
		specStr, ok := r.Spec.(string)
		if !ok {
			return fmt.Errorf("unsupported packages spec type %T for type %q; spec must be a string", r.Spec, d.Type)
		}
		d.FileBased.Spec = specStr
	}

	d.FileBased.Lock = eco.DefaultLockFile
	if r.Lock != "" {
		if eco.DefaultLockFile == "" {
			return fmt.Errorf("lock is not supported for type %q", d.Type)
		}
		d.FileBased.Lock = r.Lock
	}

	return nil
}
