package storage

import (
	"errors"
	"strings"
)

var (
	ErrBrokenImage   = errors.New("broken image")
	ErrImageNotFound = errors.New("image not found")
	ErrNotSupported  = errors.New("not supported")
)

func IsErrBrokenImage(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ErrBrokenImage.Error())
}
