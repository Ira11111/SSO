package auth

import (
	service "AuthJWT/internal/services/auth"
	v "AuthJWT/internal/validator"
	"context"
	"errors"
	auth "github.com/Ira11111/protos/v4/gen/go/sso"
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
		role string,
	) (int64, error)
	RefreshToken(
		ctx context.Context,
		refreshToken string,
	) (string, string, error)
	AddRole(
		ctx context.Context,
		role string,
	) ([]string, error)
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
	if err := v.ValidateLoginRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed")
	}
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

func (s *serverAPI) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	if err := v.ValidateRegisterRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed")
	}
	// сервисный слой
	userId, err := s.auth.RegisterNewUser(ctx, req.Email, req.Password, req.Role)
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
	accessToken, refToken, err := s.auth.RefreshToken(ctx, req.RefreshToken)
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

func (s *serverAPI) AddRole(ctx context.Context, req *auth.AddRoleRequest) (*auth.AddRoleResponse, error) {
	if err := v.ValidateAddRoleRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "validation failed")
	}

	roles, err := s.auth.AddRole(ctx, req.Role)
	if err != nil {
		if errors.Is(err, service.ErrRoleAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "role already exists")
		}
		if errors.Is(err, service.ErrUserRolesNotFound) {
			return nil, status.Error(codes.NotFound, "user roles not found")
		}
		if errors.Is(err, service.ErrRoleDoesNotExist) {
			return nil, status.Error(codes.NotFound, "role does not exist")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &auth.AddRoleResponse{
		Roles: roles,
	}, nil
}
