package config

import (
	"fmt"

	"github.com/samber/lo"

	"github.com/werf/werf/v2/pkg/sbom"
	"github.com/werf/werf/v2/pkg/util/option"
)

type rawMetaBuildSbom struct {
	// Use a pointer to detect presence under strict YAML unmarshal:
	// - nil => omitted
	// - non-nil => specified
	Enable *bool `yaml:"enable,omitempty"`

	// Use a pointer to detect presence under strict YAML unmarshal:
	// - nil => omitted
	// - non-nil => specified (possibly empty string, which we reject)
	Standard *string `yaml:"standard,omitempty"`

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

	if err := s.applySbomAndValidate(); err != nil {
		return err
	}

	return nil
}

// applySbomAndValidate applies and validates SBOM.
//
// Rules:
// - if both enable and standard are omitted: enable=false, standard=cyclonedx@1.6
// - if standard is specified: require enable=true (and validate standard)
// - if enable=false is specified without standard: standard defaults to cyclonedx@1.6
// - if enable=true is specified: require standard (and it currently supports only cyclonedx@1.6)
func (s *rawMetaBuildSbom) applySbomAndValidate() error {
	const defaultStandard = sbom.StandardTypeCycloneDX16

	enableSpecified := s.Enable != nil
	standardSpecified := s.Standard != nil

	// Both omitted -> set full defaults and exit.
	if !enableSpecified && !standardSpecified {
		s.Enable = lo.ToPtr(false)
		s.Standard = lo.ToPtr(defaultStandard.String())
		return nil
	}

	// standard specified -> require enable=true (explicitly).
	if standardSpecified && !enableSpecified {
		return fmt.Errorf("meta build sbom config: field 'enable' must be explicitly set to true when 'standard' is specified")
	}

	// enable specified:
	if enableSpecified {
		enable := option.PtrValueOrDefault(s.Enable, false)

		// enable=true -> require standard.
		if enable && !standardSpecified {
			return fmt.Errorf("meta build sbom config: field 'standard' is required when 'enable' is true")
		}

		// enable=false -> default standard if omitted.
		if !enable && !standardSpecified {
			s.Standard = lo.ToPtr(defaultStandard.String())
			return nil
		}
	}

	// At this point standard must be present -> validate it.
	if s.Standard == nil || *s.Standard == "" {
		return fmt.Errorf("meta build sbom config: field 'standard' must not be empty")
	}

	parsed, err := sbom.StandardTypeString(*s.Standard)
	if err != nil {
		return fmt.Errorf("meta build sbom config: unsupported 'standard' value %q: %w", *s.Standard, err)
	}

	if parsed != defaultStandard {
		return fmt.Errorf(
			"meta build sbom config: unsupported 'standard' value %q (only %q is supported)",
			*s.Standard,
			defaultStandard.String(),
		)
	}

	return nil
}

func (s *rawMetaBuildSbom) toDirective() *MetaBuildSbom {
	if s == nil {
		return nil
	}

	// At this point UnmarshalYAML guarantees Standard is set to the only supported value.
	return &MetaBuildSbom{
		Enable:   option.PtrValueOrDefault(s.Enable, false),
		Standard: sbom.StandardTypeCycloneDX16,
	}
}
