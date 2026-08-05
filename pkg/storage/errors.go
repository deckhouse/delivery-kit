package storage

import (
	"errors"
)

var (
	ErrBrokenImage   = errors.New("broken image")
	ErrImageNotFound = errors.New("image not found")
	ErrNotSupported  = errors.New("not supported")
	ErrStageNotFound = errors.New("stage not found")
	ErrStageRejected = errors.New("stage rejected")
)

func IsErrBrokenImage(err error) bool {
	return errors.Is(err, ErrBrokenImage)
}

func IsErrStageNotFound(err error) bool {
	return errors.Is(err, ErrStageNotFound)
}

func IsErrStageUnavailable(err error) bool {
	return errors.Is(err, ErrStageNotFound) || errors.Is(err, ErrBrokenImage) || errors.Is(err, ErrStageRejected)
}
