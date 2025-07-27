package validator

import (
	auth "github.com/Ira11111/protos/v4/gen/go/sso"
	v "github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type validRegisterRequest struct {
	Email    string `validate:"email,required"`
	Password string `validate:"gt=8,required"`
	Role     string `validate:"required,oneof=customer seller worker"`
}

type validLoginRequest struct {
	Email    string `validate:"email,required"`
	Password string `validate:"gt=8,required"`
}
type validAddRoleRequest struct {
	Role string `validate:"required,oneof=customer seller worker"`
}

func ValidateRegisterRequest(req *auth.RegisterRequest) error {
	valStruct := validRegisterRequest{
		Email:    req.Email,
		Password: req.Password,
		Role:     req.Role,
	}
	return validate(valStruct)
}

func ValidateLoginRequest(req *auth.LoginRequest) error {
	valStruct := validLoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}
	return validate(valStruct)
}

func ValidateAddRoleRequest(req *auth.AddRoleRequest) error {
	valStruct := validAddRoleRequest{
		Role: req.Role,
	}
	return validate(valStruct)
}

func validate(valStruct interface{}) error {
	validator := v.New()
	if err := validator.Struct(valStruct); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}
