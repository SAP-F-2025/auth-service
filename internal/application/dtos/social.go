package dtos

import (
	"time"

	"github.com/google/uuid"
)

type SocialAccountResponse struct {
	ID          uuid.UUID `json:"id"`
	Provider    string    `json:"provider"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	AvatarURL   *string   `json:"avatar_url"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

type SocialLoginRequest struct {
	Code     string `json:"code" validate:"required"`
	State    string `json:"state" validate:"required"`
	Provider string `json:"provider" validate:"required,oneof=google microsoft"`
}
