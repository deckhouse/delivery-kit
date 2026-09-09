package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/samber/lo"
)

const packageSecretPathPrefix = "/run/secrets/"

func parsePackageSecretReference(value string) (string, bool) {
	secretID, ok := strings.CutPrefix(value, packageSecretPathPrefix)
	if !ok || secretID == "" || strings.ContainsRune(secretID, '/') {
		return "", false
	}
	return secretID, true
}

func formatEnvVarsWithOptions(env map[string]string, options PackagesCommandsOptions) string {
	if len(env) == 0 {
		return ""
	}

	keys := lo.Keys(env)
	sort.Strings(keys)

	parts := lo.Map(keys, func(k string, _ int) string {
		value := env[k]
		secretID, isSecretReference := parsePackageSecretReference(value)
		if isSecretReference {
			if _, declared := options.DeclaredSecretIDs[secretID]; declared {
				return formatSecretReference(k, secretID)
			}
		}
		return fmt.Sprintf(`%s=%q`, k, value)
	})
	return strings.Join(parts, " ")
}

func formatSecretReference(name, secretID string) string {
	return fmt.Sprintf(`%s="$(<%s%s)"`, name, packageSecretPathPrefix, secretID)
}

func formatSecretVar(name string) string {
	return fmt.Sprintf(
		`%[1]s="${%[1]s-$([ -r %[2]s%[1]s ] && printf '%%s' "$(<%[2]s%[1]s)" || true)}"`,
		name, packageSecretPathPrefix,
	)
}
