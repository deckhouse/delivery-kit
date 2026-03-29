package checker

import "fmt"

type SbomType string

const (
	SbomTypeOSS       SbomType = "oss"
	SbomTypeContainer SbomType = "container"
)

func (t SbomType) String() string {
	return string(t)
}

func ParseSbomType(s string) (SbomType, error) {
	switch SbomType(s) {
	case SbomTypeOSS:
		return SbomTypeOSS, nil
	case SbomTypeContainer:
		return SbomTypeContainer, nil
	default:
		return "", fmt.Errorf("invalid sbom type %q: must be one of %s, %s", s, SbomTypeOSS, SbomTypeContainer)
	}
}
