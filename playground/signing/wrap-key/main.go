// wrap-key converts a plain PKCS#8 PEM private key into the sigstore-encrypted
// PEM ("ENCRYPTED DELIVERY-KIT PRIVATE KEY") that delivery-kit loads for
// --sign-key. Uses an empty passphrase to match delivery-kit's SkipPassword.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: wrap-key <in-pkcs8.pem> <out-enc.pem>")
		os.Exit(2)
	}
	in, out := os.Args[1], os.Args[2]

	raw, err := os.ReadFile(in)
	if err != nil {
		panic(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		panic("input is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		panic(fmt.Errorf("parse pkcs8: %w", err))
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	enc, err := encrypted.Encrypt(der, []byte{})
	if err != nil {
		panic(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED DELIVERY-KIT PRIVATE KEY",
		Bytes: enc,
	})
	if err := os.WriteFile(out, pemBytes, 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote", out)
}
