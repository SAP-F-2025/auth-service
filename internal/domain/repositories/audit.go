package repositories

import (
	"context"
	"time"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
	"github.com/google/uuid"
)

type AuditRepository interface {
	// Audit logging
	Log(ctx context.Context, log *entities.AuditLog) error
	GetByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*entities.AuditLog, error)
	GetByAction(ctx context.Context, action string, limit, offset int) ([]*entities.AuditLog, error)
	GetByDateRange(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]*entities.AuditLog, error)
	Search(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*entities.AuditLog, error)

	// Security monitoring
	GetFailedLogins(ctx context.Context, timeWindow time.Duration) ([]*entities.AuditLog, error)
	GetSuspiciousActivity(ctx context.Context, userID uuid.UUID, timeWindow time.Duration) ([]*entities.AuditLog, error)
	GetAdminActions(ctx context.Context, timeWindow time.Duration) ([]*entities.AuditLog, error)

	// Cleanup
	DeleteOldLogs(ctx context.Context, olderThan time.Time) error
}
