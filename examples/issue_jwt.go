package main

import (
	"context"
	"fmt"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/axent-pl/credentials/jwks"
	"github.com/axent-pl/credentials/jwt"
)

func IssueJWT(key sig.SignatureKeyer) {
	issueParams := jwt.JWTIssueParams{
		Issuer: "ACME",
		Exp:    20 * time.Second,
		Key:    key,
	}
	issuer := jwt.JWTIssuer{}
	artifacts, _ := issuer.Issue(context.Background(), common.Principal{Subject: "ACME"}, issueParams)
	accessToken, _ := common.ArtifactWithKind(artifacts, common.ArtifactAccessToken)

	fmt.Println("Token: ", string(accessToken.Bytes))
}

func IssueJWKS(key sig.SignatureKeyer) {
	issueParams := jwks.JWKSIssueParams{
		Keys: []sig.SignatureKeyer{key},
	}
	issueer := jwks.JWKSIssuer{}
	artifacts, _ := issueer.Issue(context.Background(), common.Principal{Subject: "ACME"}, issueParams)
	jwks, _ := common.ArtifactWithKind(artifacts, common.ArtifactJSONWebKeySet)

	fmt.Println("JWKS: ", string(jwks.Bytes))
}
