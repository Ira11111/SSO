package auth

import (
	service "AuthJWT/internal/services/auth"
	"context"
	"errors"
	"fmt"
	auth "github.com/Ira11111/protos/v3/gen/go/sso"
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
	) (string, string, error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (int64, error)
	RefreshToken(
		ctx context.Context,
		refreshToken string,
	) (string, string, error)
}

type serverAPI struct {
	auth.UnimplementedAuthServer
	auth *service.Auth
}

func Register(gRPC *grpc.Server, a *service.Auth) {
	//регистрирует обработчик grpc сервера
	auth.RegisterAuthServer(gRPC, &serverAPI{auth: a})
}

func (s *serverAPI) Login(ctx context.Context, req *auth.AuthRequest) (*auth.LoginResponse, error) {
	//if err := validateRequest(req); err != nil {
	//	return nil, status.Error(codes.InvalidArgument, "validation failed")
	//}
	accessToken, RefToken, err := s.auth.Login(ctx, req.Email, req.Password)

	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &auth.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: RefToken,
	}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *auth.AuthRequest) (*auth.RegisterResponse, error) {
	fmt.Println(req)
	if err := validateAuthRequest(req); err != nil {
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

func (s *serverAPI) RefreshToken(ctx context.Context, req *auth.RefreshRequest) (*auth.RefreshResponse, error) {
	accessToken, refToken, err := s.auth.RefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrTokenExpired) {
			return nil, status.Error(codes.InvalidArgument, "token expired")
		}
		if errors.Is(err, service.ErrTokenRevoked) {
			return nil, status.Error(codes.Unauthenticated, "token revoked")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &auth.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refToken,
	}, nil
}

type validAuthRequest struct {
	Email    string `validate:"email,required"`
	Password string `validate:"gt=8,required"`
}

func validateAuthRequest(req *auth.AuthRequest) error {
	valStruct := validAuthRequest{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}
	validator := v.New()
	if err := validator.Struct(valStruct); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}
