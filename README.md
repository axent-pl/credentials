## Usage

### JWT Issue
```golang
signatureKey, _ := rsa.GenerateKey(rand.Reader, 2048)
issueParams := JWTIssueParams{
    Issuer: "acme-issuer",
    Exp:    20 * time.Second,
    Key: JWTIssueKey{
        PrivateKey: signatureKey,
        Alg:        "RS256",
    },
}
issuer := JWTIssuer{}
// Issues JWT token for principal
artifacts, _ := issuer.Issue(context.Background(), Principal{Subject: "subject-id"}, issueParams)
accessToken, _ := ArtifactWithKind(artifacts, ArtifactAccessToken)
```

### JWT Input
```golang

```


### Standards

 [iana](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)