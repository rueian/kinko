package status

import "errors"

var (
	ErrNoParams = errors.New("should not be empty")
	ErrNoPlugin = errors.New("sealingPlugin not supported")
	ErrBadData  = errors.New("bad data")
)
