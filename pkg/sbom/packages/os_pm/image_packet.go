package os_pm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// imagePacketLabelPrefix is the label namespace the packages build puts the
// package metadata of a final image into.
const imagePacketLabelPrefix = "pkg."

// ErrNoImagePacketLabels reports that an image carries no package metadata at
// all, or carries it without the fields that identify a package. It separates
// "this image is not a package" from a package declaration that is broken.
var ErrNoImagePacketLabels = errors.New("no package labels")

// imagePacketDigestRegexp accepts only a canonical lowercase sha256 digest, the
// form an image reference resolves to.
var imagePacketDigestRegexp = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imagePacketListFields are the fields the index render splits by comma, the
// rest of the labels stay strings.
var imagePacketListFields = []string{"arch", "depends", "srcLanguages"}

// imagePacketBoolFields are the fields the index record holds as JSON booleans
// while the image label holds them as a string.
var imagePacketBoolFields = []string{"default"}

// imagePacketRequiredFields identify the package; without them there is nothing
// to describe.
var imagePacketRequiredFields = []string{"name", "version", "type", "arch"}

// PacketJSONFromImageLabels builds the package index JSON of a single image out
// of its pkg.* config labels and the digest the image reference resolved to.
//
// digest is authoritative: it is the only field not taken from the labels, and
// a pkg.digest label that disagrees with it is rejected as a forgery. Labels
// outside the pkg.* namespace are ignored, unknown pkg.* fields are kept as the
// strings they are. The declared package name, version, type and platform are
// not checked here: that is the business of the caller that declared them.
func PacketJSONFromImageLabels(ctx context.Context, labels map[string]string, digest string) (json.RawMessage, error) {
	if !imagePacketDigestRegexp.MatchString(digest) {
		return nil, fmt.Errorf("packet JSON from image labels: invalid: digest %q is not a canonical sha256 digest", digest)
	}

	fields, err := imagePacketFields(labels)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("packet JSON from image labels: %w", ErrNoImagePacketLabels)
	}

	for _, name := range imagePacketRequiredFields {
		if fields[name] == "" {
			return nil, fmt.Errorf("packet JSON from image labels: %w: %s is missing or empty", ErrNoImagePacketLabels, name)
		}
	}

	if labeled, ok := fields["digest"]; ok && labeled != digest {
		return nil, fmt.Errorf("packet JSON from image labels: invalid: label digest %q contradicts image digest %q", labeled, digest)
	}
	fields["digest"] = digest

	packet := make(map[string]json.RawMessage, len(fields))
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		value, err := imagePacketValue(name, fields[name])
		if err != nil {
			return nil, fmt.Errorf("packet JSON from image labels: invalid: %s: %w", name, err)
		}
		packet[name] = value
	}

	data, err := json.Marshal(packet)
	if err != nil {
		return nil, fmt.Errorf("packet JSON from image labels: %w", err)
	}

	return json.RawMessage(data), nil
}

func imagePacketFields(labels map[string]string) (map[string]string, error) {
	fields := make(map[string]string, len(labels))
	for _, key := range slices.Sorted(maps.Keys(labels)) {
		if !strings.HasPrefix(key, imagePacketLabelPrefix) {
			continue
		}

		name := strings.TrimPrefix(key, imagePacketLabelPrefix)
		if name == "" {
			return nil, fmt.Errorf("packet JSON from image labels: invalid: label %q has an empty field name", key)
		}
		// The JSON encoder silently replaces invalid UTF-8 with U+FFFD, so reject it here.
		if !utf8.ValidString(name) || !utf8.ValidString(labels[key]) {
			return nil, fmt.Errorf("packet JSON from image labels: invalid: label %q is not valid UTF-8", key)
		}

		fields[name] = labels[key]
	}

	return fields, nil
}

func imagePacketValue(name, value string) (json.RawMessage, error) {
	switch {
	case slices.Contains(imagePacketListFields, name):
		items := strings.Split(value, ",")
		for _, item := range items {
			if item == "" {
				return nil, fmt.Errorf("%q has an empty item", value)
			}
		}

		return marshalImagePacketValue(items)
	case slices.Contains(imagePacketBoolFields, name):
		// Label values are strings even where the index record holds a boolean,
		// so only the two canonical spellings are a boolean here.
		switch value {
		case "true":
			return json.RawMessage("true"), nil
		case "false":
			return json.RawMessage("false"), nil
		default:
			return nil, fmt.Errorf("%q is not true or false", value)
		}
	default:
		return marshalImagePacketValue(value)
	}
}

func marshalImagePacketValue(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return json.RawMessage(data), nil
}
