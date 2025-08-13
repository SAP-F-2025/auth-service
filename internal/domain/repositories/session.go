package repositories

import (
	"context"
	"time"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
	"github.com/google/uuid"
)

type SessionRepository interface {
	// Session management
	Create(ctx context.Context, session *entities.UserSession) error
	GetByToken(ctx context.Context, token string) (*entities.UserSession, error)
	GetByID(ctx context.Context, id uuid.UUID) (*entities.UserSession, error)
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*entities.UserSession, error)
	Update(ctx context.Context, session *entities.UserSession) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByToken(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error

	// Session validation
	IsTokenValid(ctx context.Context, token string) (bool, error)
	RefreshSession(ctx context.Context, sessionID uuid.UUID, newAccessToken, newRefreshToken string, expiresAt time.Time) error

	// Session monitoring
	GetActiveSessions(ctx context.Context, limit, offset int) ([]*entities.UserSession, error)
	CountUserActiveSessions(ctx context.Context, userID uuid.UUID) (int, error)
}
