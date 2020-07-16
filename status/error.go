package status

import "errors"

var (
	ErrEmptyParam = errors.New("should not be empty")
	ErrNoProvider = errors.New("not supported provider")
	ErrBadData    = errors.New("bad data")
)
