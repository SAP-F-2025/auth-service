package dtos

import (
	"time"

	"github.com/google/uuid"
)

type UserResponse struct {
	ID          uuid.UUID     `json:"id"`
	Username    string        `json:"username"`
	Email       string        `json:"email"`
	FirstName   string        `json:"first_name"`
	LastName    string        `json:"last_name"`
	IsActive    bool          `json:"is_active"`
	IsVerified  bool          `json:"is_verified"`
	Role        *RoleResponse `json:"role,omitempty"`
	MFAEnabled  bool          `json:"mfa_enabled"`
	AvatarURL   *string       `json:"avatar_url"`
	LastLoginAt *time.Time    `json:"last_login_at"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

type SessionResponse struct {
	ID         uuid.UUID `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	IsActive   bool      `json:"is_active"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type UpdateUserRequest struct {
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,min=1,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,min=1,max=100"`
	Username  *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
}
