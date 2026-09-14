package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/alessio/shellescape"
)

const (
	packageSecretsDir = "/run/secrets/"

	packageEnvNamespaceSecret     = "secret"
	packageEnvNamespaceSecretPath = "secret_path"
)

var (
	packageEnvReferenceRe = regexp.MustCompile(`%(secret_path|secret):([^%]*)%`)
	packageSecretIDRe     = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
)

type packageEnvPart struct {
	literal   string
	namespace string
	secretID  string
}

func splitPackageEnvValue(value string) ([]packageEnvPart, error) {
	var parts []packageEnvPart

	end := 0
	for _, match := range packageEnvReferenceRe.FindAllStringSubmatchIndex(value, -1) {
		namespace, secretID := value[match[2]:match[3]], value[match[4]:match[5]]
		if !packageSecretIDRe.MatchString(secretID) {
			return nil, fmt.Errorf("invalid secret id %q in %q: must match %s", secretID, value, packageSecretIDRe)
		}

		if match[0] > end {
			parts = append(parts, packageEnvPart{literal: value[end:match[0]]})
		}
		parts = append(parts, packageEnvPart{namespace: namespace, secretID: secretID})
		end = match[1]
	}

	if end < len(value) {
		parts = append(parts, packageEnvPart{literal: value[end:]})
	}

	return parts, nil
}

func formatPackageEnvValue(value string) string {
	parts, err := splitPackageEnvValue(value)
	if err != nil {
		// Malformed references are rejected while parsing the config, so reaching this point
		// means the value never went through validatePackageEnvValues: keep it literal.
		return shellescape.Quote(value)
	}

	if len(parts) == 0 {
		return shellescape.Quote("")
	}

	formatted := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part.namespace {
		case packageEnvNamespaceSecret:
			formatted = append(formatted, fmt.Sprintf(`"$(<%s%s)"`, packageSecretsDir, part.secretID))
		case packageEnvNamespaceSecretPath:
			formatted = append(formatted, shellescape.Quote(packageSecretsDir+part.secretID))
		default:
			formatted = append(formatted, shellescape.Quote(part.literal))
		}
	}

	return strings.Join(formatted, "")
}

func validatePackageEnvValues(rawPackages []*rawPackagesDirective, secrets []Secret) error {
	declaredSecretIDs := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		declaredSecretIDs[secret.Id] = struct{}{}
	}

	for index, rawPackage := range rawPackages {
		for name, value := range rawPackage.Env {
			parts, err := splitPackageEnvValue(value)
			if err != nil {
				return newDetailedConfigError(fmt.Sprintf("packages[%d].env[%q]: %s", index, name, err), rawPackage, rawPackage.docForErrors())
			}

			for _, part := range parts {
				if part.namespace == "" {
					continue
				}
				if _, declared := declaredSecretIDs[part.secretID]; !declared {
					return newDetailedConfigError(fmt.Sprintf("packages[%d].env[%q] references secret %q, which is not declared in the `secrets` section", index, name, part.secretID), rawPackage, rawPackage.docForErrors())
				}
			}
		}
	}

	return nil
}
