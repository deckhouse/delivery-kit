package config

import "fmt"

var pythonAliases = map[string]PackagesDirectiveType{
	"uv":     PackagesDirectiveTypePythonUV,
	"pip":    PackagesDirectiveTypePythonPip,
	"poetry": PackagesDirectiveTypePythonPoetry,
}

var pythonDefaults = map[PackagesDirectiveType]struct{ Spec, Lock string }{
	PackagesDirectiveTypePythonUV:     {Spec: pythonUVDefaultSpec, Lock: pythonUVDefaultLock},
	PackagesDirectiveTypePythonPip:    {Spec: pythonPipDefaultSpec, Lock: pythonPipDefaultLock},
	PackagesDirectiveTypePythonPoetry: {Spec: pythonPoetryDefaultSpec, Lock: pythonPoetryDefaultLock},
}

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
	if canonical, ok := pythonAliases[r.Type]; ok {
		r.Type = string(canonical)
	}

	d := &PackagesDirective{
		Type: PackagesDirectiveType(r.Type),
	}

	switch d.Type {
	case PackagesDirectiveTypeOSPM:
		if err := r.fillOSPMSpec(d); err != nil {
			return nil, err
		}
	case PackagesDirectiveTypeGoMod:
		r.fillGoModSpec(d)
	case PackagesDirectiveTypePythonUV, PackagesDirectiveTypePythonPip, PackagesDirectiveTypePythonPoetry:
		if err := r.fillPythonSpec(d); err != nil {
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

func (r *rawPackagesDirective) fillGoModSpec(d *PackagesDirective) {
	d.GoMod.Workdir = r.Workdir

	d.GoMod.Spec = goModDefaultSpec
	if spec, ok := r.Spec.(string); ok && spec != "" {
		d.GoMod.Spec = spec
	}

	d.GoMod.Lock = goModDefaultLock
	if r.Lock != "" {
		d.GoMod.Lock = r.Lock
	}
}

func (r *rawPackagesDirective) fillPythonSpec(d *PackagesDirective) error {
	d.Python.Manager = d.Type
	d.Python.Workdir = r.Workdir

	defaults := pythonDefaults[d.Type]
	d.Python.Spec = defaults.Spec
	if spec, ok := r.Spec.(string); ok && spec != "" {
		d.Python.Spec = spec
	} else if r.Spec != nil {
		return fmt.Errorf("spec must be a string for type %q", d.Type)
	}

	d.Python.Lock = defaults.Lock
	if r.Lock != "" {
		d.Python.Lock = r.Lock
	}

	return nil
}
