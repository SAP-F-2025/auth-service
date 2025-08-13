package dtos

import (
	"time"

	"github.com/google/uuid"
)

type RoleResponse struct {
	ID          uuid.UUID             `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Description string                `json:"description"`
	IsActive    bool                  `json:"is_active"`
	Permissions []*PermissionResponse `json:"permissions,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

type PermissionResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateRoleRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50"`
	DisplayName string `json:"display_name" validate:"required,min=3,max=100"`
	Description string `json:"description" validate:"max=255"`
}

type UpdateRoleRequest struct {
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=3,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=255"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

type CreatePermissionRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=100"`
	Resource    string `json:"resource" validate:"required,min=3,max=50"`
	Action      string `json:"action" validate:"required,min=3,max=50"`
	Description string `json:"description" validate:"max=255"`
}

type UpdatePermissionRequest struct {
	Description *string `json:"description,omitempty" validate:"omitempty,max=255"`
}

type UserPermissionResponse struct {
	ID         uuid.UUID           `json:"id"`
	Permission *PermissionResponse `json:"permission"`
	IsGranted  bool                `json:"is_granted"`
	Reason     string              `json:"reason"`
	ExpiresAt  *time.Time          `json:"expires_at"`
	CreatedAt  time.Time           `json:"created_at"`
	CreatedBy  uuid.UUID           `json:"created_by"`
}

type GrantUserPermissionRequest struct {
	UserID       uuid.UUID  `json:"user_id" validate:"required"`
	PermissionID uuid.UUID  `json:"permission_id" validate:"required"`
	IsGranted    bool       `json:"is_granted"`
	Reason       string     `json:"reason" validate:"required,min=10,max=255"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}
