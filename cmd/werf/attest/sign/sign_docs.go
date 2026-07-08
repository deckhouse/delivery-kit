package sign

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Create a signed OCI attestation and attach it to a container image.

The predicate file is wrapped in an in-toto Statement v1, then in a DSSE envelope,
signed with the specified key, and pushed to the container registry as an OCI artifact
with a subject reference to the parent image.`

	docs.LongMD = "Create a signed OCI attestation and attach it to a container image.\n\n" +
		"The predicate file is wrapped in an in-toto Statement v1, then in a DSSE envelope, " +
		"signed with the specified key, and pushed to the container registry as an OCI artifact " +
		"with a subject reference to the parent image."

	return docs
}
