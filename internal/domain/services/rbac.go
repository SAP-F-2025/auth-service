package services

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/application/dtos"
	"github.com/google/uuid"
)

type RBACService interface {
	// Role management
	CreateRole(ctx context.Context, req *dtos.CreateRoleRequest) (*dtos.RoleResponse, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*dtos.RoleResponse, error)
	GetRoleByName(ctx context.Context, name string) (*dtos.RoleResponse, error)
	ListRoles(ctx context.Context) ([]*dtos.RoleResponse, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, req *dtos.UpdateRoleRequest) (*dtos.RoleResponse, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error

	// Permission management
	CreatePermission(ctx context.Context, req *dtos.CreatePermissionRequest) (*dtos.PermissionResponse, error)
	GetPermission(ctx context.Context, permissionID uuid.UUID) (*dtos.PermissionResponse, error)
	ListPermissions(ctx context.Context) ([]*dtos.PermissionResponse, error)
	UpdatePermission(ctx context.Context, permissionID uuid.UUID, req *dtos.UpdatePermissionRequest) (*dtos.PermissionResponse, error)
	DeletePermission(ctx context.Context, permissionID uuid.UUID) error
}
