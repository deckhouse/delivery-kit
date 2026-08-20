package config

import (
	"fmt"
	"regexp"
)

type rawPackagesDirective struct {
	Type    string            `yaml:"type,omitempty"`
	Spec    interface{}       `yaml:"spec,omitempty"`
	Workdir string            `yaml:"workdir,omitempty"`
	Lock    string            `yaml:"lock,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`

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

var posixEnvNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (r *rawPackagesDirective) toDirective(index int) (*PackagesDirective, error) {
	d := &PackagesDirective{
		Type: PackagesDirectiveType(r.Type),
	}

	if d.Type == PackagesDirectiveTypeOSPM {
		if r.Workdir != "" {
			return nil, fmt.Errorf("workdir is not supported for type %q", d.Type)
		}
		if r.Spec == nil {
			return nil, fmt.Errorf("the `spec` is required for type %q", d.Type)
		}

		specList, ok := r.Spec.([]interface{})
		if !ok {
			if specStr, isStr := r.Spec.(string); isStr {
				return nil, fmt.Errorf("unsupported packages spec type %q for type %q; use inline package list instead of file path", specStr, d.Type)
			}
			return nil, fmt.Errorf("unsupported packages spec type %T for type %q; spec must be a list of package names", r.Spec, d.Type)
		}

		pkgs := make([]string, len(specList))
		for i, item := range specList {
			pkgStr, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid package name type %T in packages[%d].spec[%d]", item, index, i)
			}
			pkgs[i] = pkgStr
		}

		if len(pkgs) == 0 {
			return nil, fmt.Errorf("packages[%d].spec must not be empty for type %q", index, d.Type)
		}

		d.Spec = PackagesSpec{Packages: pkgs}
	} else {
		if err := r.fillFileBasedSpec(d); err != nil {
			return nil, err
		}
	}

	d.Env = r.Env

	for key := range d.Env {
		if !posixEnvNameRe.MatchString(key) {
			return nil, fmt.Errorf("invalid environment variable name %q in packages[%d].env: must match POSIX naming pattern [a-zA-Z_][a-zA-Z0-9_]*", key, index)
		}
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
	d.FileBased.Spec = eco.DefaultSpecFile
	d.FileBased.Lock = eco.DefaultLockFile

	if r.Spec != nil {
		specStr, ok := r.Spec.(string)
		if !ok {
			return fmt.Errorf("unsupported packages spec type %T for type %q; spec must be a string", r.Spec, d.Type)
		}
		d.FileBased.Spec = specStr
	}

	if r.Lock != "" {
		if eco.DefaultLockFile == "" {
			return fmt.Errorf("lock is not supported for type %q", d.Type)
		}
		d.FileBased.Lock = r.Lock
	}

	return nil
}
