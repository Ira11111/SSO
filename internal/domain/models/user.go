package models

type User struct {
	// модель пользователя
	Id           int64
	Email        string
	PasswordHash []byte
}
