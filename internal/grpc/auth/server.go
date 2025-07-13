package auth

import (
	service "AuthJWT/internal/services/auth"
	"context"
	"errors"
	"fmt"
	auth "github.com/Ira11111/protos/gen/go/sso"
	v "github.com/go-playground/validator/v10"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int32,
	) (string, error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(
		ctx context.Context,
		userId int64,
	) (bool, error)
}

type serverAPI struct {
	auth.UnimplementedAuthServer
	auth *service.Auth
}

func Register(gRPC *grpc.Server, a *service.Auth) {
	//регистрирует обработчик grpc сервера
	auth.RegisterAuthServer(gRPC, &serverAPI{auth: a})
}

func (s *serverAPI) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	if err := validateLoginRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed")
	}
	token, err := s.auth.Login(ctx, req.Email, req.Password, req.AppId)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			return nil, status.Error(codes.NotFound, "user not found")
		case errors.Is(err, service.ErrInvalidCredentials):
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		case errors.Is(err, service.ErrInvalidAppId):
			return nil, status.Error(codes.NotFound, "application not found")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	return &auth.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	fmt.Println(req)
	if err := validateRegisterRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed")
	}
	// сервисный слой
	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &auth.RegisterResponse{
		UserId: userId,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *auth.IsAdminRequest) (*auth.IsAdminResponse, error) {

	if err := validateIsAdminRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// сервисный слой
	res, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &auth.IsAdminResponse{
		IsAdmin: res,
	}, nil
}

type validLogin struct {
	Email    string `validate:"email,required"`
	Password string `validate:"required"`
	AppId    int32  `validate:"gt=0,required"`
}

type validRegister struct {
	Email    string `validate:"email,required"`
	Password string `validate:"gt=8,required"`
}

func validateLoginRequest(req *auth.LoginRequest) error {
	valStruct := validLogin{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
		AppId:    req.GetAppId(),
	}
	validator := v.New()
	return validator.Struct(valStruct)
}

func validateRegisterRequest(req *auth.RegisterRequest) error {
	valStruct := validRegister{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}
	validator := v.New()
	if err := validator.Struct(valStruct); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

func validateIsAdminRequest(req *auth.IsAdminRequest) error {
	validator := v.New()
	if err := validator.Var(req.GetUserId(), "required"); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}
