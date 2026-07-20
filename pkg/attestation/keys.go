package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func LoadSigner(keyRef string, passFunc cryptoutils.PassFunc) (signature.Signer, error) {
	if strings.HasPrefix(keyRef, hashivault.ReferenceScheme) {
		return hashivault.LoadSignerVerifier(keyRef, crypto.SHA256)
	}

	pemBytes, err := os.ReadFile(keyRef)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	return loadSignerFromPEM(pemBytes, passFunc)
}

func LoadVerifiers(keyRefs []string) ([]signature.Verifier, error) {
	var verifiers []signature.Verifier
	for _, keyRef := range keyRefs {
		pemBytes, err := os.ReadFile(keyRef)
		if err != nil {
			return nil, fmt.Errorf("read key %q: %w", keyRef, err)
		}

		pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key %q: %w", keyRef, err)
		}

		v, err := signature.LoadVerifier(pubKey, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("load verifier from %q: %w", keyRef, err)
		}

		verifiers = append(verifiers, v)
	}
	return verifiers, nil
}

func loadSignerFromPEM(pemBytes []byte, passFunc cryptoutils.PassFunc) (signature.SignerVerifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}

	var privKey crypto.PrivateKey
	var err error

	switch block.Type {
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q: expected PRIVATE KEY, EC PRIVATE KEY, or RSA PRIVATE KEY", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASignerVerifier(k, crypto.SHA256)
	case *rsa.PrivateKey:
		return signature.LoadRSAPKCS1v15SignerVerifier(k, crypto.SHA256)
	case ed25519.PrivateKey:
		return signature.LoadED25519SignerVerifier(k)
	default:
		return nil, fmt.Errorf("unsupported key type %T", privKey)
	}
}
