package validate

import "github.com/werf/werf/v2/cmd/werf/docs/structs"

func GetDocs() structs.DocsStruct {
	var docs structs.DocsStruct

	docs.Long = `Validate CycloneDX JSON SBOM file(s) against ISPRAS validation schemas.`

	docs.LongMD = "Validate CycloneDX JSON SBOM file(s) against ISPRAS validation schemas."

	return docs
}
