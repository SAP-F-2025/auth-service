package services

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/application/dtos"
	"github.com/google/uuid"
)

type AuthService interface {
	// Authentication
	Login(ctx context.Context, req *dtos.LoginRequest) (*dtos.LoginResponse, error)
	Logout(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error
	RefreshToken(ctx context.Context, refreshToken string) (*dtos.TokenResponse, error)

	// Registration
	Register(ctx context.Context, req *dtos.RegisterRequest) (*dtos.UserResponse, error)
	VerifyEmail(ctx context.Context, token string) error
	ResendVerification(ctx context.Context, email string) error

	// Password management
	ChangePassword(ctx context.Context, userID uuid.UUID, req *dtos.ChangePasswordRequest) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, req *dtos.ResetPasswordRequest) error

	// Session management
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*dtos.SessionResponse, error)
	RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error
	ValidateToken(ctx context.Context, token string) (*dtos.UserResponse, error)
}
