package dtos

import (
	"time"
)

type MFASetupResponse struct {
	Secret    string `json:"secret"`
	QRCode    string `json:"qr_code"` // Base64 encoded QR code image
	BackupURL string `json:"backup_url"`
}

type MFABackupResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

type MFAChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type MFAVerificationRequest struct {
	Code        string `json:"code" validate:"required,len=6"`
	ChallengeID string `json:"challenge_id,omitempty"`
}
