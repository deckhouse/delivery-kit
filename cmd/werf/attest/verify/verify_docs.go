package verify

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Verify a signed attestation attached to a container image.

The attestation is pulled from the container registry, the DSSE signature is verified
against the provided public key(s), and the raw predicate JSON is printed to stdout.
If the signature is invalid, the command exits with a non-zero exit code and prints nothing.`

	docs.LongMD = "Verify a signed attestation attached to a container image.\n\n" +
		"The attestation is pulled from the container registry, the DSSE signature is verified " +
		"against the provided public key(s), and the raw predicate JSON is printed to stdout.\n" +
		"If the signature is invalid, the command exits with a non-zero exit code and prints nothing."

	return docs
}
