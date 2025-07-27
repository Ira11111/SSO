package models

type User struct {
	Id           int64
	Email        string
	PasswordHash []byte
}
