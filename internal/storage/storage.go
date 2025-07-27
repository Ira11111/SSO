package storage

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrTokenNotFound      = errors.New("token not found")
	ErrTokenAlreadyExists = errors.New("token already exists")
	ErrRoleDoesNotExist   = errors.New("role does not exist")
	ErrRoleAlreadyExists  = errors.New("role already exists")
	ErrRolesNotFound      = errors.New("roles not found")
)
