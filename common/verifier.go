package common

import (
	"context"
)

type Scheme interface {
	Kind() Kind
}
type Verifier interface {
	Kind() Kind
	VerifyAny(ctx context.Context, in Credentials, stored []Scheme) (Principal, error)
}
