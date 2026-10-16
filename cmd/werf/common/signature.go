package common

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"

	"github.com/werf/common-go/pkg/util"
	"github.com/werf/werf/v3/pkg/build/signing"
	"github.com/werf/werf/v3/pkg/config"
	"github.com/werf/werf/v3/pkg/signature"
	"github.com/werf/werf/v3/pkg/util/option"
	"github.com/werf/werf/v3/pkg/werf/exec"
)

func SetupSigningOptions(cmdData *CmdData, cmd *cobra.Command) {
	cmdData.SignManifest = new(bool)
	cmd.Flags().BoolVarP(cmdData.SignManifest, "sign-manifest", "", util.GetBoolEnvironmentDefaultFalse("WERF_SIGN_MANIFEST"),
		`Enable image manifest signing (default $WERF_SIGN_MANIFEST).
When enabled,
the private signing key must be specified with --sign-key option and
the certificate must be specified with --sign-cert option`)

	cmdData.SignKey = new(string)
	cmd.Flags().StringVarP(cmdData.SignKey, "sign-key", "", os.Getenv("WERF_SIGN_KEY"),
		"The private signing key as path to PEM file, base64-encoded PEM or hashivault://[KEY] (default $WERF_SIGN_KEY)")

	cmdData.SignCert = new(string)
	cmd.Flags().StringVarP(cmdData.SignCert, "sign-cert", "", os.Getenv("WERF_SIGN_CERT"),
		"The leaf certificate as path to PEM file or base64-encoded PEM (default $WERF_SIGN_CERT)")

	cmdData.SignIntermediates = new(string)
	cmd.Flags().StringVarP(cmdData.SignIntermediates, "sign-intermediates", "", os.Getenv("WERF_SIGN_INTERMEDIATES"),
		"The intermediate certificates as path to PEM file or base64-encoded PEM (default $WERF_SIGN_INTERMEDIATES)")
}

func GetSignManifest(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.SignManifest, false)
}

func SetupFilesSigningOptions(cmdData *CmdData, cmd *cobra.Command) {
	cmdData.SignFiles = new(bool)
	cmd.Flags().BoolVarP(cmdData.SignFiles, "sign-files", "", util.GetBoolEnvironmentDefaultTrue("WERF_SIGN_FILES"),
		`Sign the files declared with the sign directive of werf.yaml (default $WERF_SIGN_FILES or true).
When enabled and at least one image declares files to sign,
the private signing key must be specified with --sign-files-key option and
the certificate must be specified with --sign-files-cert option.
Disable to build such images without signatures`)

	cmdData.SignFilesKey = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesKey, "sign-files-key", "", os.Getenv("WERF_SIGN_FILES_KEY"),
		"The private key to sign files with as path to PEM file, base64-encoded PEM or hashivault://[KEY] (default $WERF_SIGN_FILES_KEY)")

	cmdData.SignFilesCert = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesCert, "sign-files-cert", "", os.Getenv("WERF_SIGN_FILES_CERT"),
		"The leaf certificate of the files signing key as path to PEM file or base64-encoded PEM (default $WERF_SIGN_FILES_CERT)")

	cmdData.SignFilesIntermediates = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesIntermediates, "sign-files-intermediates", "", os.Getenv("WERF_SIGN_FILES_INTERMEDIATES"),
		"The intermediate certificates of the files signing key as path to PEM file or base64-encoded PEM (default $WERF_SIGN_FILES_INTERMEDIATES)")

	cmdData.SignFilesVaultAddr = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesVaultAddr, "sign-files-vault-addr", "", os.Getenv("WERF_SIGN_FILES_VAULT_ADDR"),
		"The Vault address a hashivault:// files signing key is resolved against (default $WERF_SIGN_FILES_VAULT_ADDR, then $VAULT_ADDR)")

	cmdData.SignFilesVaultTransitPath = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesVaultTransitPath, "sign-files-vault-transit-path", "", os.Getenv("WERF_SIGN_FILES_VAULT_TRANSIT_PATH"),
		"The Vault transit engine mount of the files signing key (default $WERF_SIGN_FILES_VAULT_TRANSIT_PATH, then $TRANSIT_SECRET_ENGINE_PATH)")

	cmdData.SignFilesVaultAuthJWT = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesVaultAuthJWT, "sign-files-vault-auth-jwt", "", os.Getenv("WERF_SIGN_FILES_VAULT_AUTH_JWT"),
		"The JWT to log in to Vault with for the files signing key; when unset the Vault authentication is taken from the environment, as for --sign-key (default $WERF_SIGN_FILES_VAULT_AUTH_JWT)")

	cmdData.SignFilesVaultAuthRole = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesVaultAuthRole, "sign-files-vault-auth-role", "", os.Getenv("WERF_SIGN_FILES_VAULT_AUTH_ROLE"),
		"The Vault JWT role for --sign-files-vault-auth-jwt (default $WERF_SIGN_FILES_VAULT_AUTH_ROLE)")

	cmdData.SignFilesVaultAuthPath = new(string)
	cmd.Flags().StringVarP(cmdData.SignFilesVaultAuthPath, "sign-files-vault-auth-path", "", os.Getenv("WERF_SIGN_FILES_VAULT_AUTH_PATH"),
		"The Vault JWT auth mount for --sign-files-vault-auth-jwt (default $WERF_SIGN_FILES_VAULT_AUTH_PATH, then jwt)")
}

func GetSignFiles(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.SignFiles, false)
}

func SetupELFSigningOptions(cmdData *CmdData, cmd *cobra.Command) {
	cmdData.SignELFFiles = new(bool)
	cmd.Flags().BoolVarP(cmdData.SignELFFiles, "sign-elf-files", "", util.GetBoolEnvironmentDefaultFalse("WERF_SIGN_ELF_FILES"),
		`Enable ELF files signing (default $WERF_SIGN_ELF_FILES).
When enabled, the private signing key must be specified with --sign-key option and the certificate must be specified with --sign-cert option`)

	cmdData.BSignELFFiles = new(bool)
	cmd.Flags().BoolVarP(cmdData.BSignELFFiles, "bsign-elf-files", "", util.GetBoolEnvironmentDefaultFalse("WERF_BSIGN_ELF_FILES"),
		`Enable ELF files signing with bsign (default $WERF_BSIGN_ELF_FILES).
When enabled, the private elf key must be specified with --elf-pgp-private-key-base64 or --elf-pgp-private-key-fingerprint option`)

	cmdData.ELFPGPPrivateKeyBase64 = new(string)
	cmd.Flags().StringVarP(cmdData.ELFPGPPrivateKeyBase64, "elf-pgp-private-key-base64", "", os.Getenv("WERF_ELF_PGP_PRIVATE_KEY_BASE64"), "Base64-encoded PGP private key (default $WERF_ELF_PGP_PRIVATE_KEY_BASE64)")

	cmdData.ELFPGPPrivateKeyFingerprint = new(string)
	cmd.Flags().StringVarP(cmdData.ELFPGPPrivateKeyFingerprint, "elf-pgp-private-key-fingerprint", "", os.Getenv("WERF_ELF_PGP_PRIVATE_KEY_FINGERPRINT"), "PGP private key fingerprint (default $WERF_ELF_PGP_PRIVATE_KEY_FINGERPRINT)")

	cmdData.ELFPGPPrivateKeyPassphrase = new(string)
	cmd.Flags().StringVarP(cmdData.ELFPGPPrivateKeyPassphrase, "elf-pgp-private-key-passphrase", "", os.Getenv("WERF_ELF_PGP_PRIVATE_KEY_PASSPHRASE"), "Passphrase for the PGP private key (default $WERF_ELF_PGP_PRIVATE_KEY_PASSPHRASE)")
}

func GetSignELFFiles(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.SignELFFiles, false)
}

func GetBSignELFFiles(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.BSignELFFiles, false)
}

func SetupVerificationOptions(cmdData *CmdData, cmd *cobra.Command) {
	cmdData.VerifyManifest = new(bool)
	cmd.Flags().BoolVarP(cmdData.VerifyManifest, "verify-manifest", "", util.GetBoolEnvironmentDefaultFalse("WERF_VERIFY_MANIFEST"),
		`Enable image manifest verification (default $WERF_VERIFY_MANIFEST).
When enabled,
the root certificates must be specified with --verify-roots option`)

	defaultVerifyRoots := strings.Split(os.Getenv("WERF_VERIFY_ROOTS"), ",")
	cmdData.VerifyRoots = new([]string)
	cmd.Flags().StringArrayVarP(cmdData.VerifyRoots, "verify-roots", "", defaultVerifyRoots,
		"The root certificates as path to PEM file or base64-encoded PEM (default $WERF_VERIFY_ROOTS separated by comma)")

	defaultImageRef := strings.Split(os.Getenv("WERF_IMAGE_REF"), ",")
	cmdData.ImageRef = new([]string)
	cmd.Flags().StringArrayVarP(cmdData.ImageRef, "image-ref", "", defaultImageRef, "Verify only passed references (default $WERF_IMAGE_REF separated by comma)")
}

func GetVerifyManifest(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.VerifyManifest, false)
}

func GetVerifyRoots(cmdData *CmdData) []string {
	return option.PtrValueOrDefault(cmdData.VerifyRoots, []string{})
}

func SetupELFVerificationOptions(cmdData *CmdData, cmd *cobra.Command) {
	cmdData.VerifyELFFiles = new(bool)
	cmd.Flags().BoolVarP(cmdData.VerifyELFFiles, "verify-elf-files", "", util.GetBoolEnvironmentDefaultFalse("WERF_VERIFY_ELF_FILES"),
		`Enable ELF files verification (default $WERF_VERIFY_ELF_FILES).
When enabled, the root certificates must be specified with --verify-roots option`)

	cmdData.VerifyBSignELFFiles = new(bool)
	cmd.Flags().BoolVarP(cmdData.VerifyBSignELFFiles, "verify-bsign-elf-files", "", util.GetBoolEnvironmentDefaultFalse("WERF_VERIFY_BSIGN_ELF_FILES"),
		`Enable ELF files verification for bsign signed files (default $WERF_VERIFY_BSIGN_ELF_FILES).`)
}

func GetVerifyELFFiles(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.VerifyELFFiles, false)
}

func GetVerifyBSignELFFiles(cmdData *CmdData) bool {
	return option.PtrValueOrDefault(cmdData.VerifyBSignELFFiles, false)
}

func GetImageReferences(cmdData *CmdData) []string {
	return option.PtrValueOrDefault(cmdData.ImageRef, []string{})
}

func getSignerOptions(commonCmdData *CmdData) (signing.SignerOptions, error) {
	resolved, err := signature.ResolveSigningGate(signature.ResolveSigningGateOptions{
		SignKey:           lo.FromPtr(commonCmdData.SignKey),
		SignCert:          lo.FromPtr(commonCmdData.SignCert),
		SignIntermediates: lo.FromPtr(commonCmdData.SignIntermediates),
		SignManifest:      GetSignManifest(commonCmdData),
		SignELFFiles:      GetSignELFFiles(commonCmdData),
	})
	if err != nil {
		return signing.SignerOptions{}, err
	}
	return resolved.SignerOptions, nil
}

func getManifestSigningOptions(commonCmdData *CmdData, signer *signing.Signer) (signing.ManifestSigningOptions, error) {
	options := signing.NewManifestSigningOptions(signer)
	options.Enabled = GetSignManifest(commonCmdData)
	return options, nil
}

func getSbomSigningOptions(commonCmdData *CmdData, signer *signing.Signer) signing.SbomSigningOptions {
	options := signing.NewSbomSigningOptions(signer)
	options.Enabled = lo.FromPtr(commonCmdData.SignKey) != ""
	return options
}

func getVexSigningOptions(commonCmdData *CmdData, signer *signing.Signer) signing.VexSigningOptions {
	options := signing.NewVexSigningOptions(signer)
	options.Enabled = lo.FromPtr(commonCmdData.SignKey) != ""
	return options
}

// getFilesSigningOptions builds the signer of the sign directive. The directive is a
// requirement of the image, so when an image declares one the key and certificate are
// mandatory unless signing is switched off explicitly.
func getFilesSigningOptions(ctx context.Context, commonCmdData *CmdData, werfConfig *config.WerfConfig) (signing.FilesSigningOptions, error) {
	var signingImages []string
	for _, img := range werfConfig.Images(false) {
		stapelImg, ok := img.(config.StapelImageInterface)
		if !ok || len(stapelImg.ImageBaseConfig().Sign) == 0 {
			continue
		}
		signingImages = append(signingImages, img.GetName())
	}

	if len(signingImages) == 0 || !GetSignFiles(commonCmdData) {
		return signing.NewFilesSigningOptions(&signing.Signer{}), nil
	}

	keyRef := lo.FromPtr(commonCmdData.SignFilesKey)
	certRef := lo.FromPtr(commonCmdData.SignFilesCert)
	switch {
	case keyRef == "":
		return signing.FilesSigningOptions{}, fmt.Errorf("images %s declare files to sign: specify the signing key with --sign-files-key or pass --sign-files=false to build them unsigned", strings.Join(signingImages, ", "))
	case certRef == "":
		return signing.FilesSigningOptions{}, fmt.Errorf("images %s declare files to sign: specify the signing certificate with --sign-files-cert", strings.Join(signingImages, ", "))
	}

	signer, err := signing.NewSigner(ctx, signing.SignerOptions{
		KeyRef:           keyRef,
		CertRef:          certRef,
		IntermediatesRef: lo.FromPtr(commonCmdData.SignFilesIntermediates),
		Vault: signing.VaultOptions{
			Address:     lo.FromPtr(commonCmdData.SignFilesVaultAddr),
			TransitPath: lo.FromPtr(commonCmdData.SignFilesVaultTransitPath),
			AuthJWT:     lo.FromPtr(commonCmdData.SignFilesVaultAuthJWT),
			AuthRole:    lo.FromPtr(commonCmdData.SignFilesVaultAuthRole),
			AuthPath:    lo.FromPtr(commonCmdData.SignFilesVaultAuthPath),
		},
	})
	if err != nil {
		return signing.FilesSigningOptions{}, fmt.Errorf("create files signer: %w", err)
	}

	options := signing.NewFilesSigningOptions(signer)
	options.Enabled = true
	return options, nil
}

func getELFSigningOptions(commonCmdData *CmdData, signer *signing.Signer) (signing.ELFSigningOptions, error) {
	options := signing.NewELFSigningOptions(signer)

	if !GetSignELFFiles(commonCmdData) && !GetBSignELFFiles(commonCmdData) {
		return options, nil
	}

	if GetSignELFFiles(commonCmdData) {
		options.InHouseEnabled = true
	}

	// bsign
	{
		if !GetBSignELFFiles(commonCmdData) {
			return options, nil
		} else {
			options.BsignEnabled = true
		}

		if *commonCmdData.ELFPGPPrivateKeyPassphrase != "" {
			options.PGPPrivateKeyPassphrase = *commonCmdData.ELFPGPPrivateKeyPassphrase
		}

		if *commonCmdData.ELFPGPPrivateKeyBase64 != "" && *commonCmdData.ELFPGPPrivateKeyFingerprint != "" {
			return options, fmt.Errorf("both --elf-pgp-private-key-base64 and --elf-pgp-private-key-fingerprint params are specified, only one of them should be specified")
		} else if *commonCmdData.ELFPGPPrivateKeyBase64 == "" && *commonCmdData.ELFPGPPrivateKeyFingerprint == "" {
			return options, fmt.Errorf("either --elf-pgp-private-key-base64 or --elf-pgp-private-key-fingerprint param is required")
		}

		if *commonCmdData.ELFPGPPrivateKeyFingerprint != "" {
			options.PGPPrivateKeyFingerprint = *commonCmdData.ELFPGPPrivateKeyFingerprint
			return options, nil
		}

		// Get fingerprint and import key.
		{
			keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*commonCmdData.ELFPGPPrivateKeyBase64))
			if err != nil {
				return options, fmt.Errorf("unable to decode PGP key from base64: %w", err)
			}

			pgpKeyString := string(keyBytes)
			entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyBytes))
			if err != nil {
				return options, fmt.Errorf("unable to read PGP key: %w", err)
			}

			firstKey := entityList[0].PrimaryKey
			fingerprint := firstKey.Fingerprint
			options.PGPPrivateKeyFingerprint = fmt.Sprintf("%X", fingerprint)

			// Import PGP key.
			{
				ctx := context.Background()
				cmd := exec.CommandContextCancellation(ctx, "gpg", "--import")
				cmd.Stdin = bytes.NewBufferString(pgpKeyString)

				if options.PGPPrivateKeyPassphrase != "" {
					cmd.Args = append(cmd.Args, "--batch")
					cmd.Args = append(cmd.Args, "--passphrase=$WERF_SERVICE_ELF_PGP_PRIVATE_KEY_PASSPHRASE")
					cmd.Env = append(cmd.Env, fmt.Sprintf("WERF_SERVICE_ELF_PGP_PRIVATE_KEY_PASSPHRASE=%s", options.PGPPrivateKeyPassphrase))
				}

				err := cmd.Run()
				if err != nil {
					return options, fmt.Errorf("unable to import PGP key: %w", err)
				}
			}
		}
	}

	return options, nil
}

func GetVerifyOptions(commonCmdData *CmdData) (signature.VerifyOptions, error) {
	opts := signature.VerifyOptions{
		VerifyManifest:      GetVerifyManifest(commonCmdData),
		VerifyELFFiles:      GetVerifyELFFiles(commonCmdData),
		VerifyBSignELFFiles: GetVerifyBSignELFFiles(commonCmdData),
		Roots:               GetVerifyRoots(commonCmdData),
		References:          nil,
	}
	if len(opts.Roots) == 0 {
		return signature.VerifyOptions{}, errors.New("no root certificates specified")
	}
	if !opts.VerifyManifest && !opts.VerifyELFFiles && !opts.VerifyBSignELFFiles {
		return signature.VerifyOptions{}, errors.New("no verification targets specified. Use --verify-manifest and one of --verify-elf-files or --verify-bsign-elf-files options")
	}
	if opts.VerifyELFFiles && opts.VerifyBSignELFFiles {
		return signature.VerifyOptions{}, errors.New("both --verify-elf-files and --verify-bsign-elf-files options are specified. Use only one of them")
	}
	return opts, nil
}
