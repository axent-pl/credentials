package userpassword

type UserPasswordSchemer interface {
	GetUsername() string
	CompareUsernameAndPassword(username string, password string) error
}
