package common

import (
	"context"
)

type IssueParams interface {
	Kind() Kind
}

type Issuer interface {
	Kind() Kind
	Issue(ctx context.Context, principal Principal, issueParams IssueParams) ([]Artifact, error)
}
