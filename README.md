## Usage

### JWT Issue
```golang
signatureKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {

}
issueScheme := JWTIssueScheme{
    Issuer: "acme-issuer",
    Exp:    20 * time.Second,
    Key: JWTIssueSchemeKey{
        PrivateKey: signatureKey,
        Alg:        "RS256",
    },
}
issueParams := JWTIssueParams{}
issuer := JWTIssuer{}
artifacts, _ := issuer.Issue(context.Background(), Principal{Subject: "subject-id"}, issueScheme, issueParams)
accessToken, _ := ArtifactWithKind(artifacts, ArtifactAccessToken)
```

### JWT Input
```golang

```


### Standards

 [iana](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml)