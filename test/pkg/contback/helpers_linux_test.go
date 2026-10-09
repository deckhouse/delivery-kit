package contback

import (
	"bytes"
	"io"
	"sync"
)

type cleanupTraceObserver struct {
	output  bytes.Buffer
	marker  string
	started chan struct{}
	once    sync.Once
}

var _ io.Writer = (*cleanupTraceObserver)(nil)

func (observer *cleanupTraceObserver) Write(data []byte) (int, error) {
	count, err := observer.output.Write(data)
	if bytes.Contains(observer.output.Bytes(), []byte(observer.marker)) {
		observer.once.Do(func() { close(observer.started) })
	}
	return count, err
}
