package examples

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/axent-pl/credentials/common"
	"github.com/axent-pl/credentials/common/sig"
	"github.com/axent-pl/credentials/jwt"
)

func IssueJWT() {
	signatureKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issueParams := jwt.JWTIssueParams{
		Issuer: "ACME",
		Exp:    20 * time.Second,
		Key: sig.SignatureKey{
			Key: signatureKey,
			Alg: sig.SigAlgRS256,
		},
	}
	issuer := &jwt.JWTIssuer{}
	artifacts, _ := issuer.Issue(context.Background(), common.Principal{Subject: "ACME"}, issueParams)
	accessToken, _ := common.ArtifactWithKind(artifacts, common.ArtifactAccessToken)

	fmt.Println(accessToken)
}
