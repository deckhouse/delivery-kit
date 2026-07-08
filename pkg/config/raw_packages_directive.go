package config

import "fmt"

type rawPackagesDirective struct {
	Type    string `yaml:"type,omitempty"`
	Spec    string `yaml:"spec,omitempty"`
	Workdir string `yaml:"workdir,omitempty"`
	Lock    string `yaml:"lock,omitempty"`

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

	d.FileBased.Workdir = r.Workdir

	d.FileBased.Spec = eco.DefaultSpec
	if r.Spec != "" {
		d.FileBased.Spec = r.Spec
	}

	d.FileBased.Lock = eco.DefaultLock
	if r.Lock != "" {
		if eco.DefaultLock == "" {
			return fmt.Errorf("lock is not supported for type %q", d.Type)
		}
		d.FileBased.Lock = r.Lock
	}

	return nil
}
