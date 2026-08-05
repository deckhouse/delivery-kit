package ls

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `List all attestations attached to a container image.

Shows a table of attestations with their predicate types, digests, and signature status.`

	docs.LongMD = "List all attestations attached to a container image.\n\n" +
		"Shows a table of attestations with their predicate types, digests, and signature status."

	return docs
}
