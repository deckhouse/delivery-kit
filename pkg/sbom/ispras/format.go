package ispras

import "fmt"

type Format string

const (
	FormatOSS       Format = "oss"
	FormatContainer Format = "container"
)

func (f Format) String() string {
	return string(f)
}

func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatOSS:
		return FormatOSS, nil
	case FormatContainer:
		return FormatContainer, nil
	default:
		return "", fmt.Errorf("invalid ispras format %q: must be one of %s, %s", s, FormatOSS, FormatContainer)
	}
}
