package jsobserver

const (
	ProtocolVersion = 1
	LogPath         = "/tmp/.werf-js-observer/events.jsonl"
)

// Event records package contributions to individual outputs, not the union of
// dependencies read during a build. Paths and digests describe the emitted bytes.
type Event struct {
	Version int      `json:"version"`
	Outputs []Output `json:"outputs,omitempty"`
	Warning string   `json:"warning,omitempty"`
}

type Output struct {
	Path     string    `json:"path"`
	Digest   string    `json:"digest"`
	Packages []Package `json:"packages"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
