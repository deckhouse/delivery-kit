package get

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Get an attestation attached to a container image and print the predicate to stdout.

The attestation is pulled from the container registry, the DSSE envelope is unwrapped,
the in-toto statement is parsed, and the raw predicate JSON is printed.
Signature is NOT verified — use "werf attest verify" for that.`

	docs.LongMD = "Get an attestation attached to a container image and print the predicate to stdout.\n\n" +
		"The attestation is pulled from the container registry, the DSSE envelope is unwrapped, " +
		"the in-toto statement is parsed, and the raw predicate JSON is printed.\n" +
		"Signature is NOT verified — use `werf attest verify` for that."

	return docs
}
