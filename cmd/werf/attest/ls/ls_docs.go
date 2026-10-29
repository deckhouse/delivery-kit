package ls

import "github.com/werf/werf/v3/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `List all attestations attached to a container image.

Shows a table of attestations with their predicate types, digests, and signature status.

For a multi-platform image index the attestations of every platform manifest are listed
under their platform, and the attestations attached to the index itself (image-level kinds
such as OpenVEX) under the platform "index".`

	docs.LongMD = "List all attestations attached to a container image.\n\n" +
		"Shows a table of attestations with their predicate types, digests, and signature status.\n\n" +
		"For a multi-platform image index the attestations of every platform manifest are listed " +
		"under their platform, and the attestations attached to the index itself (image-level kinds " +
		"such as OpenVEX) under the platform `index`."

	return docs
}
