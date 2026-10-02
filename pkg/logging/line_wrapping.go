package logging

import (
	"context"

	"github.com/werf/logboek"
)

// DoWithoutLineWrapping runs f with line wrapping of the context logger suspended
// and restores the previous mode afterwards. Output of external tools goes through
// it: logboek splits a line longer than the stream width and marks the split with a
// wrap character, which breaks grepping and copying of the original message.
//
// The mode is a property of the stream shared by every logger bound to the context,
// so f must be the only thing logging while it runs.
func DoWithoutLineWrapping(ctx context.Context, f func()) {
	streams := logboek.Context(ctx).Streams()
	wasEnabled := streams.IsLineWrappingEnabled()
	streams.DisableLineWrapping()
	defer func() {
		if wasEnabled {
			streams.EnableLineWrapping()
		}
	}()

	f()
}
