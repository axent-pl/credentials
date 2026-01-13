package clientsecret

type ClientSecretSchemer interface {
	GetClientId() string
	CompareIdAndSecret(id string, secret string) error
}
