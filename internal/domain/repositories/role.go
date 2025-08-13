package repositories

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/domain/entities"
	"github.com/google/uuid"
)

type RoleRepository interface {
	// Role management
	Create(ctx context.Context, role *entities.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Role, error)
	GetByName(ctx context.Context, name string) (*entities.Role, error)
	List(ctx context.Context) ([]*entities.Role, error)
	Update(ctx context.Context, role *entities.Role) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Permission management
	CreatePermission(ctx context.Context, permission *entities.Permission) error
	GetPermissionByID(ctx context.Context, id uuid.UUID) (*entities.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*entities.Permission, error)
	ListPermissions(ctx context.Context) ([]*entities.Permission, error)
	UpdatePermission(ctx context.Context, permission *entities.Permission) error
	DeletePermission(ctx context.Context, id uuid.UUID) error

	// Role-Permission relationships
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*entities.Permission, error)
	GetPermissionsByRoleName(ctx context.Context, roleName string) ([]*entities.Permission, error)

	// User-Permission overrides
	GrantUserPermission(ctx context.Context, userPermission *entities.UserPermission) error
	RevokeUserPermission(ctx context.Context, userID, permissionID uuid.UUID) error
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*entities.UserPermission, error)

	// Permission checking
	UserHasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
	GetUserAllPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
}
