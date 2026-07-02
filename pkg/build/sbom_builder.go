package build

import (
	"fmt"
	"strings"

	"github.com/werf/werf/v2/pkg/image"
)

const containerFactoryRegistry = "registry.deckhouse.io/container-factory"

func isGolangBuilderImage(name string) bool {
	return strings.HasPrefix(name, fmt.Sprintf("%s/builder/golang", containerFactoryRegistry))
}

func isAlpineBuilderImage(name string) bool {
	return strings.HasPrefix(name, fmt.Sprintf("%s/builder/alpine", containerFactoryRegistry))
}

func isTrustedBuilderImage(labels map[string]string) bool {
	if labels == nil {
		return false
	}
	return labels[image.DeckhouseInternalBuilderLabel] == "true"
}
