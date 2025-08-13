package services

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/application/dtos"
	"github.com/google/uuid"
)

type MFAService interface {
	// MFA setup
	GenerateSecret(ctx context.Context, userID uuid.UUID) (*dtos.MFASetupResponse, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, code string) (*dtos.MFABackupResponse, error)
	DisableMFA(ctx context.Context, userID uuid.UUID, password string) error

	// MFA verification
	VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) error
	VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) error

	// Recovery
	GenerateNewBackupCodes(ctx context.Context, userID uuid.UUID, password string) (*dtos.MFABackupResponse, error)

	// MFA challenges
	RequiresMFA(ctx context.Context, userID uuid.UUID) (bool, error)
	CreateMFAChallenge(ctx context.Context, userID uuid.UUID) (*dtos.MFAChallengeResponse, error)
	CompleteMFAChallenge(ctx context.Context, challengeID string, code string) (*dtos.TokenResponse, error)
}
