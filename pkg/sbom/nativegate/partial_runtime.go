package nativegate

import (
	"bytes"
	"encoding/json"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// A fragment is an image that is not run: a scratch image holding the output of one
// build, assembled into a running image together with its siblings. Its dynamic files
// name a loader and need objects that stand in those siblings, so the closure this gate
// reads inside one image is not there to be read - not because nothing states it, but
// because this image is only a part of what states it.
//
// A recipe declaring such an image a partial runtime says exactly that, and nothing more:
// what is absent from the image is not held against it, while everything the image does
// hold is read as it always was. The closure itself is still proven, in the image that is
// actually run and holds all of the parts.
//
// The published document says so, and names what was left open, so that a reader of the
// SBOM is never told that a closure was checked when it was not.
const partialRuntimeProperty = "dk:runtime-closure/v1"

// partialRuntimeClosure is the published form of that statement: which closure the
// document carries, and the names - a loader path, a SONAME - this image resolved
// nothing for.
type partialRuntimeClosure struct {
	Schema     string   `json:"schema"`
	Closure    string   `json:"closure"`
	Unresolved []string `json:"unresolved"`
}

func partialRuntimeClosureProperty(unresolved []string) (cdx.Property, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(partialRuntimeClosure{Schema: partialRuntimeProperty, Closure: "partial", Unresolved: slices.Sorted(slices.Values(unresolved))}); err != nil {
		return cdx.Property{}, err
	}

	return cdx.Property{Name: partialRuntimeProperty, Value: string(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))}, nil
}

// missingRuntimeDependencyError is a name a file needs that this image holds no file
// for. It is the one runtime refusal a partial runtime tolerates, so it is answered as a
// value the caller can recognize rather than as text.
type missingRuntimeDependencyError struct {
	soname string
}

func (e missingRuntimeDependencyError) Error() string {
	return "missing runtime dependency " + e.soname
}
