package vex

import (
	"encoding/json"
	"fmt"

	"github.com/werf/werf/v2/pkg/attestation"
)

// Predicate URIs and media types of VEX artifacts. attestation.PredicateKindOpenVEX
// owns them; these aliases exist so VEX code reads in its own terms.
var (
	// VEXPredicateURI is the in-toto predicate type of unsigned OpenVEX documents.
	VEXPredicateURI = attestation.PredicateKindOpenVEX.UnsignedType

	// VEXPredicateURIUnversioned is the predicate type of signed OpenVEX
	// attestations: stock cosign resolves its `openvex` well-known type to this
	// URI, so signed artifacts must carry it to be verifiable out of the box.
	VEXPredicateURIUnversioned = attestation.PredicateKindOpenVEX.SignedType

	// VEXPredicateTypes lists every predicate URI denoting the OpenVEX attestation kind.
	VEXPredicateTypes = attestation.PredicateKindOpenVEX.Types()
)

const (
	// DSSEMediaType is the media type for DSSE envelopes used by VEX artifacts.
	DSSEMediaType = attestation.DSSEMediaType

	// InTotoMediaType is the media type for in-toto statements used by VEX artifacts.
	InTotoMediaType = attestation.InTotoMediaType
)

// openVEXDocument is a minimal representation of an OpenVEX JSON-LD document
// used for format validation.
type openVEXDocument struct {
	Context    string          `json:"@context"`
	Statements json.RawMessage `json:"statements"`
}

// ValidateVEXDocument validates a VEX document file for correct OpenVEX JSON-LD format.
// Returns nil on success or a descriptive error.
func ValidateVEXDocument(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("VEX document is empty")
	}

	if !json.Valid(data) {
		return fmt.Errorf("VEX document is not valid JSON")
	}

	var doc openVEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("VEX document is not valid OpenVEX: %w", err)
	}

	if doc.Context != VEXPredicateURI {
		return fmt.Errorf("VEX document has unexpected @context %q, expected %q", doc.Context, VEXPredicateURI)
	}

	return nil
}
