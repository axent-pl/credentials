package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/logx"
	"github.com/axent-pl/credentials/common/sig"
)

type JWKSIssueParams struct {
	Keys []sig.SignatureKeyer
}

type jwksPayload struct {
	Issuer       string           `json:"issuer,omitempty"`
	ValidMethods []string         `json:"valid_methods,omitempty"`
	Keys         []sig.JSONWebKey `json:"keys"`
}

func (JWKSIssueParams) Kind() common.Kind { return common.JWT }

type JWKSIssuer struct{}

var _ common.Issuer = JWKSIssuer{}

func (JWKSIssuer) Kind() common.Kind { return common.JWT }

func (iss JWKSIssuer) Issue(ctx context.Context, principal common.Principal, issueParams common.IssueParams) ([]common.Artifact, error) {
	jwksIssueParams, ok := issueParams.(JWKSIssueParams)
	if !ok {
		logx.L().Debug("could not cast IssueParams to JWKSIssueParams", "context", ctx)
		return nil, common.ErrInternal
	}

	jwks := jwksPayload{
		Issuer: string(principal.Subject),
		Keys:   make([]sig.JSONWebKey, 0),
	}
	validMethods := make([]string, 0)
	validMethodSet := make(map[string]struct{})
	for _, key := range jwksIssueParams.Keys {
		jwk, err := key.GetJWK()
		if err != nil {
			logx.L().Debug("could not generate JWK from key", "context", ctx, "error", err)
			return nil, fmt.Errorf("%v: could not generate JWK from key", common.ErrInternal)
		}
		if alg := key.GetAlg().String(); alg != "unknown" {
			if _, ok := validMethodSet[alg]; !ok {
				validMethodSet[alg] = struct{}{}
				validMethods = append(validMethods, alg)
			}
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	if len(validMethods) > 0 {
		jwks.ValidMethods = validMethods
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		logx.L().Debug("could not marshal JWKS", "context", ctx, "error", err)
		return nil, fmt.Errorf("%v: could not marshal JWKS", common.ErrInternal)
	}

	artifacts := make([]common.Artifact, 0)
	artifacts = append(artifacts, common.Artifact{
		Kind:      common.ArtifactJSONWebKeySet,
		MediaType: "application/json",
		Bytes:     jwksBytes,
	})

	return artifacts, nil
}
