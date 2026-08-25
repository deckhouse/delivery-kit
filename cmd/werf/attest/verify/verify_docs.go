package verify

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Verify a signed attestation attached to a container image.

The attestation is pulled from the container registry, the DSSE signature is verified
against the provided public key(s), and the raw predicate JSON is printed to stdout.
If the signature is invalid, the command exits with a non-zero exit code and prints nothing.

When the reference resolves to a multi-platform image index and --platform is not set,
the attestations of all platforms in the index are verified: a per-platform result table
is printed instead of the predicate, and the command succeeds only if every platform
carries a valid signed attestation.`

	docs.LongMD = "Verify a signed attestation attached to a container image.\n\n" +
		"The attestation is pulled from the container registry, the DSSE signature is verified " +
		"against the provided public key(s), and the raw predicate JSON is printed to stdout.\n" +
		"If the signature is invalid, the command exits with a non-zero exit code and prints nothing.\n\n" +
		"When the reference resolves to a multi-platform image index and `--platform` is not set, " +
		"the attestations of all platforms in the index are verified: a per-platform result table " +
		"is printed instead of the predicate, and the command succeeds only if every platform " +
		"carries a valid signed attestation."

	return docs
}
