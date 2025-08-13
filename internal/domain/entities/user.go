package entities

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Username     string    `json:"username" gorm:"type:varchar(50);uniqueIndex;not null"`
	Email        string    `json:"email" gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash string    `json:"-" gorm:"type:varchar(255);not null"`
	FirstName    string    `json:"first_name" gorm:"type:varchar(100);not null"`
	LastName     string    `json:"last_name" gorm:"type:varchar(100);not null"`
	IsActive     bool      `json:"is_active" gorm:"default:true;index"`
	IsVerified   bool      `json:"is_verified" gorm:"default:false"`

	// Role relationship
	RoleID uuid.UUID `json:"role_id" gorm:"type:uuid;not null;index"`
	Role   *Role     `json:"role,omitempty" gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`

	// MFA fields
	MFAEnabled  bool     `json:"mfa_enabled" gorm:"default:false"`
	MFASecret   string   `json:"-" gorm:"type:varchar(255)"`
	BackupCodes []string `json:"-" gorm:"type:text[];default:'{}'"`

	// Social login fields
	GoogleID    *string `json:"-" gorm:"type:varchar(255);uniqueIndex"`
	MicrosoftID *string `json:"-" gorm:"type:varchar(255);uniqueIndex"`
	AvatarURL   *string `json:"avatar_url" gorm:"type:text"`

	// Relationships
	Sessions        []UserSession    `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	SocialAccounts  []SocialAccount  `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	UserPermissions []UserPermission `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	AuditLogs       []AuditLog       `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`

	// Audit fields
	CreatedAt   time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
	LastLoginAt *time.Time     `json:"last_login_at"`
}

// BeforeCreate GORM hook
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for User
func (User) TableName() string {
	return "users"
}

// UserSession represents an active user session
type UserSession struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	AccessToken  string    `json:"-" gorm:"type:varchar(500);uniqueIndex;not null"`
	RefreshToken string    `json:"-" gorm:"type:varchar(500);uniqueIndex;not null"`
	DeviceInfo   string    `json:"device_info" gorm:"type:varchar(255)"`
	IPAddress    string    `json:"ip_address" gorm:"type:inet"`
	UserAgent    string    `json:"user_agent" gorm:"type:text"`
	IsActive     bool      `json:"is_active" gorm:"default:true;index"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"not null;index"`

	// Relationship
	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (s *UserSession) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for UserSession
func (UserSession) TableName() string {
	return "user_sessions"
}

// SocialAccount represents linked social accounts
type SocialAccount struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID      uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Provider    string    `json:"provider" gorm:"type:varchar(50);not null;index"` // google, microsoft
	ProviderID  string    `json:"provider_id" gorm:"type:varchar(255);not null"`
	Email       string    `json:"email" gorm:"type:varchar(255)"`
	DisplayName string    `json:"display_name" gorm:"type:varchar(255)"`
	AvatarURL   *string   `json:"avatar_url" gorm:"type:text"`
	AccessToken string    `json:"-" gorm:"type:text"`
	IsActive    bool      `json:"is_active" gorm:"default:true"`

	// Relationship
	User User `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// Audit fields
	CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BeforeCreate GORM hook
func (s *SocialAccount) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for SocialAccount
func (SocialAccount) TableName() string {
	return "social_accounts"
}

// Unique constraint for user_id + provider
func (SocialAccount) UniqueIndexes() []string {
	return []string{"idx_social_accounts_user_provider", "idx_social_accounts_provider_id"}
}
