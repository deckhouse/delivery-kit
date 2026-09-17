package externalref

import "errors"

var ErrEmptyURL = errors.New("empty url in resolve response")

type ResolveResult struct {
	PURL          string   `json:"purl"`
	PURLRequested string   `json:"purl_requested"`
	URL           string   `json:"url"`
	Kind          string   `json:"kind"`
	Confirmed     bool     `json:"confirmed"`
	Status        string   `json:"status"`
	Confidence    float64  `json:"confidence"`
	Provider      string   `json:"provider"`
	Resolution    string   `json:"resolution"`
	Sources       []Source `json:"sources"`
	Hashes        []Hash   `json:"hashes"`
}

// Hash is a digest of the artifact the resolved URL points to. The resolver
// computes it for source distributions, whose archive the ISPRAS SBOM schema
// requires to be identified by a GOST R 34.11-2012 (Streebog) digest.
type Hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type Source struct {
	Kind      string     `json:"kind"`
	Meta      SourceMeta `json:"meta"`
	Provider  string     `json:"provider"`
	PickedURL string     `json:"picked_url"`
}

type SourceMeta struct {
	HTTPStatus int    `json:"http_status"`
	RequestURL string `json:"request_url"`
}
