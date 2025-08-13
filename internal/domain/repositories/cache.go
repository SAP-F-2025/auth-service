package repositories

import (
	"context"
	"time"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
)

type CacheRepository interface {
	// General cache operations
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string, dest interface{}) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)

	// OAuth state management
	SetOAuthState(ctx context.Context, state string, oauthState *entities.OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*entities.OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error

	// Session caching
	SetSessionCache(ctx context.Context, token string, userID string, expiration time.Duration) error
	GetSessionCache(ctx context.Context, token string) (string, error)
	DeleteSessionCache(ctx context.Context, token string) error

	// Rate limiting
	IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int, error)
	GetRateLimit(ctx context.Context, key string) (int, error)
	ResetRateLimit(ctx context.Context, key string) error

	// Permission caching
	SetUserPermissions(ctx context.Context, userID string, permissions []string, expiration time.Duration) error
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
	DeleteUserPermissions(ctx context.Context, userID string) error

	// MFA temporary codes
	SetMFACode(ctx context.Context, userID string, code string, expiration time.Duration) error
	GetMFACode(ctx context.Context, userID string) (string, error)
	DeleteMFACode(ctx context.Context, userID string) error

	// Email verification
	SetVerificationCode(ctx context.Context, email string, code string, expiration time.Duration) error
	GetVerificationCode(ctx context.Context, email string) (string, error)
	DeleteVerificationCode(ctx context.Context, email string) error

	// Password reset
	SetPasswordResetCode(ctx context.Context, email string, code string, expiration time.Duration) error
	GetPasswordResetCode(ctx context.Context, email string) (string, error)
	DeletePasswordResetCode(ctx context.Context, email string) error
}
