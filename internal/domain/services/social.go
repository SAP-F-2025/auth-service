package services

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/application/dtos"
	"github.com/google/uuid"
)

type SocialLoginService interface {
	// Social authentication
	GoogleLogin(ctx context.Context, code, state string) (*dtos.LoginResponse, error)
	MicrosoftLogin(ctx context.Context, code, state string) (*dtos.LoginResponse, error)

	// Account linking
	LinkGoogleAccount(ctx context.Context, userID uuid.UUID, code string) error
	LinkMicrosoftAccount(ctx context.Context, userID uuid.UUID, code string) error
	UnlinkSocialAccount(ctx context.Context, userID uuid.UUID, provider string) error
	GetLinkedAccounts(ctx context.Context, userID uuid.UUID) ([]*dtos.SocialAccountResponse, error)

	// Social profile management
	UpdateProfileFromSocial(ctx context.Context, userID uuid.UUID, provider string) error
	SyncAvatarFromSocial(ctx context.Context, userID uuid.UUID, provider string) error
}
