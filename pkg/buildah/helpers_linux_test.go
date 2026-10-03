package buildah

import (
	"errors"
	"io"
)

var _ io.Reader = failingReader{}

type failingReader struct{}

func (r failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}
