package entities

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role represents a user role in RBAC
type Role struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string    `json:"name" gorm:"type:varchar(50);uniqueIndex;not null"` // student, teacher, proctor, admin
	DisplayName string    `json:"display_name" gorm:"type:varchar(100);not null"`
	Description string    `json:"description" gorm:"type:text"`
	IsActive    bool      `json:"is_active" gorm:"default:true"`

	// Many-to-many relationship with permissions
	Permissions []Permission `json:"permissions,omitempty" gorm:"many2many:role_permissions;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// One-to-many relationship with users
	Users []User `json:"-" gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for Role
func (Role) TableName() string {
	return "roles"
}

// Permission represents a specific permission
type Permission struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string    `json:"name" gorm:"type:varchar(100);uniqueIndex;not null"` // assessment.create, session.monitor
	Resource    string    `json:"resource" gorm:"type:varchar(50);not null;index"`    // assessment, session, user
	Action      string    `json:"action" gorm:"type:varchar(50);not null;index"`      // create, read, update, delete, monitor
	Description string    `json:"description" gorm:"type:text"`

	// Many-to-many relationship with roles
	Roles []Role `json:"-" gorm:"many2many:role_permissions;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// One-to-many relationship with user permissions
	UserPermissions []UserPermission `json:"-" gorm:"foreignKey:PermissionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for Permission
func (Permission) TableName() string {
	return "permissions"
}

// RolePermission represents the many-to-many relationship (auto-created by GORM)
type RolePermission struct {
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// TableName sets the table name for RolePermission
func (RolePermission) TableName() string {
	return "role_permissions"
}

// UserPermission represents user-specific permission overrides
type UserPermission struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID       uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	PermissionID uuid.UUID  `json:"permission_id" gorm:"type:uuid;not null;index"`
	IsGranted    bool       `json:"is_granted" gorm:"not null"` // true = grant, false = deny
	Reason       string     `json:"reason" gorm:"type:text;not null"`
	ExpiresAt    *time.Time `json:"expires_at" gorm:"index"`
	CreatedBy    uuid.UUID  `json:"created_by" gorm:"type:uuid;not null"`

	// Relationships
	User       User       `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Permission Permission `json:"permission,omitempty" gorm:"foreignKey:PermissionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Creator    User       `json:"-" gorm:"foreignKey:CreatedBy;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (up *UserPermission) BeforeCreate(tx *gorm.DB) error {
	if up.ID == uuid.Nil {
		up.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for UserPermission
func (UserPermission) TableName() string {
	return "user_permissions"
}
