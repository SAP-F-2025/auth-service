package entities

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OAuthClient represents OAuth2 clients
type OAuthClient struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	ClientID     string    `json:"client_id" gorm:"type:varchar(100);uniqueIndex;not null"`
	ClientSecret string    `json:"-" gorm:"type:varchar(255);not null"`
	Name         string    `json:"name" gorm:"type:varchar(100);not null"`
	Description  string    `json:"description" gorm:"type:text"`
	RedirectURIs []string  `json:"redirect_uris" gorm:"type:text[];not null;default:'{}'"`
	Scopes       []string  `json:"scopes" gorm:"type:text[];not null;default:'{}'"`
	IsPublic     bool      `json:"is_public" gorm:"default:false"`
	IsActive     bool      `json:"is_active" gorm:"default:true"`
	CreatedBy    uuid.UUID `json:"created_by" gorm:"type:uuid;not null"`

	// Relationships
	Creator            User                     `json:"-" gorm:"foreignKey:CreatedBy;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	AuthorizationCodes []OAuthAuthorizationCode `json:"-" gorm:"foreignKey:ClientID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	AccessTokens       []OAuthAccessToken       `json:"-" gorm:"foreignKey:ClientID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (c *OAuthClient) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for OAuthClient
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// OAuthAuthorizationCode represents OAuth2 authorization codes
type OAuthAuthorizationCode struct {
	ID                  uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Code                string     `json:"code" gorm:"type:varchar(255);uniqueIndex;not null"`
	ClientID            uuid.UUID  `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID              uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	RedirectURI         string     `json:"redirect_uri" gorm:"type:text;not null"`
	Scopes              []string   `json:"scopes" gorm:"type:text[];default:'{}'"`
	CodeChallenge       *string    `json:"code_challenge" gorm:"type:varchar(255)"`
	CodeChallengeMethod *string    `json:"code_challenge_method" gorm:"type:varchar(10)"`
	ExpiresAt           time.Time  `json:"expires_at" gorm:"not null;index"`
	UsedAt              *time.Time `json:"used_at"`

	// Relationships
	Client OAuthClient `json:"-" gorm:"foreignKey:ClientID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	User   User        `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// BeforeCreate GORM hook
func (c *OAuthAuthorizationCode) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for OAuthAuthorizationCode
func (OAuthAuthorizationCode) TableName() string {
	return "oauth_authorization_codes"
}

// OAuthAccessToken represents OAuth2 access tokens
type OAuthAccessToken struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Token     string     `json:"-" gorm:"type:varchar(500);uniqueIndex;not null"`
	ClientID  uuid.UUID  `json:"client_id" gorm:"type:uuid;not null;index"`
	UserID    uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	Scopes    []string   `json:"scopes" gorm:"type:text[];default:'{}'"`
	ExpiresAt time.Time  `json:"expires_at" gorm:"not null;index"`
	RevokedAt *time.Time `json:"revoked_at"`

	// Relationships
	Client OAuthClient `json:"-" gorm:"foreignKey:ClientID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	User   User        `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

// BeforeCreate GORM hook
func (t *OAuthAccessToken) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for OAuthAccessToken
func (OAuthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

// OAuthState represents OAuth state for CSRF protection (stored in Redis)
type OAuthState struct {
	State     string     `json:"state"`
	Provider  string     `json:"provider"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// Constants for roles
const (
	RoleStudent = "student"
	RoleTeacher = "teacher"
	RoleProctor = "proctor"
	RoleAdmin   = "admin"
)

// Constants for permissions
const (
	// Assessment permissions
	PermAssessmentCreate  = "assessment.create"
	PermAssessmentRead    = "assessment.read"
	PermAssessmentUpdate  = "assessment.update"
	PermAssessmentDelete  = "assessment.delete"
	PermAssessmentPublish = "assessment.publish"

	// Session permissions
	PermSessionTake    = "session.take"
	PermSessionMonitor = "session.monitor"
	PermSessionManage  = "session.manage"
	PermSessionReview  = "session.review"

	// User permissions
	PermUserRead        = "user.read"
	PermUserUpdate      = "user.update"
	PermUserDelete      = "user.delete"
	PermUserManageRoles = "user.manage_roles"

	// Result permissions
	PermResultRead   = "result.read"
	PermResultManage = "result.manage"

	// Admin permissions
	PermAdminSystem  = "admin.system"
	PermAdminAudit   = "admin.audit"
	PermAdminReports = "admin.reports"
)

// Constants for social providers
const (
	ProviderGoogle    = "google"
	ProviderMicrosoft = "microsoft"
)

// Constants for audit actions
const (
	ActionLogin             = "login"
	ActionLogout            = "logout"
	ActionRegister          = "register"
	ActionPasswordChange    = "password_change"
	ActionPasswordReset     = "password_reset"
	ActionMFAEnabled        = "mfa_enabled"
	ActionMFADisabled       = "mfa_disabled"
	ActionRoleChanged       = "role_changed"
	ActionPermissionGranted = "permission_granted"
	ActionPermissionRevoked = "permission_revoked"
)
