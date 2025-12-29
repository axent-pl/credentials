package common

import "errors"

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidInput = errors.New("bad input")
var ErrInternal = errors.New("internal error")
