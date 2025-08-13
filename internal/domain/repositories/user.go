package repositories

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
	"github.com/google/uuid"
)

type UserRepository interface {
	// Basic CRUD
	Create(ctx context.Context, user *entities.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	GetByUsername(ctx context.Context, username string) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Social login related
	GetBySocialID(ctx context.Context, provider, providerID string) (*entities.User, error)
	LinkSocialAccount(ctx context.Context, socialAccount *entities.SocialAccount) error
	UnlinkSocialAccount(ctx context.Context, userID uuid.UUID, provider string) error
	GetSocialAccounts(ctx context.Context, userID uuid.UUID) ([]*entities.SocialAccount, error)

	// Authentication related
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	SetMFASecret(ctx context.Context, userID uuid.UUID, secret string) error
	EnableMFA(ctx context.Context, userID uuid.UUID) error
	DisableMFA(ctx context.Context, userID uuid.UUID) error
	SetBackupCodes(ctx context.Context, userID uuid.UUID, codes []string) error

	// User management
	List(ctx context.Context, limit, offset int) ([]*entities.User, int, error)
	Search(ctx context.Context, query string, limit, offset int) ([]*entities.User, int, error)
	UpdateRole(ctx context.Context, userID, roleID uuid.UUID, reason string) error

	// Account verification
	VerifyAccount(ctx context.Context, userID uuid.UUID) error
	SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
}
