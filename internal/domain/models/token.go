package models

import "time"

type Token struct {
	Id        int64
	Token     []byte
	UserId    int64
	ExpiresAt time.Time
	Revoked   bool
}
