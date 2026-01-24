package errors

import "errors"

var (
	ErrNilEndpointSpecificationOverview = errors.New("nil endpoint specification overview")
	ErrNilSessionInput                  = errors.New("nil session input")
)
