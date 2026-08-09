package vex

import (
	"encoding/json"
	"fmt"
)

const (
	// VEXPredicateURI is the in-toto predicate type for OpenVEX documents.
	VEXPredicateURI = "https://openvex.dev/ns/v0.2.0"

	// DSSEMediaType is the media type for DSSE envelopes used by VEX artifacts.
	DSSEMediaType = "application/vnd.dsse.envelope.v1+json"

	// InTotoMediaType is the media type for in-toto statements used by VEX artifacts.
	InTotoMediaType = "application/vnd.in-toto+json"
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
