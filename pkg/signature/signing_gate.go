package signature

import (
	"fmt"

	"github.com/werf/werf/v2/pkg/build/signing"
)

type ResolvedSigningOptions struct {
	SignerOptions          signing.SignerOptions
	ManifestSigningOptions signing.ManifestSigningOptions
	SbomSigningOptions     signing.SbomSigningOptions
}

type ResolveSigningGateOptions struct {
	SignKey           string
	SignCert          string
	SignIntermediates string
	SignManifest      bool
	SignELFFiles      bool
}

func ResolveSigningGate(opts ResolveSigningGateOptions) (ResolvedSigningOptions, error) {
	sbomEnabled := opts.SignKey != ""
	manifestEnabled := opts.SignManifest

	needSigner := sbomEnabled || manifestEnabled || opts.SignELFFiles
	if !needSigner {
		return ResolvedSigningOptions{}, nil
	}

	if opts.SignKey == "" {
		return ResolvedSigningOptions{}, fmt.Errorf("signing key is required (the private signing key must be specified with --sign-key option)")
	}
	if opts.SignCert == "" {
		return ResolvedSigningOptions{}, fmt.Errorf("signing certificate is required (the public signing certificate must be specified with --sign-cert option)")
	}

	return ResolvedSigningOptions{
		SignerOptions: signing.SignerOptions{
			KeyRef:           opts.SignKey,
			CertRef:          opts.SignCert,
			IntermediatesRef: opts.SignIntermediates,
		},
		ManifestSigningOptions: signing.ManifestSigningOptions{Enabled: manifestEnabled},
		SbomSigningOptions:     signing.SbomSigningOptions{Enabled: sbomEnabled},
	}, nil
}
