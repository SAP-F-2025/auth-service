package entities

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AuditLog represents security audit events
type AuditLog struct {
	ID         uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID     *uuid.UUID     `json:"user_id" gorm:"type:uuid;index"`
	Action     string         `json:"action" gorm:"type:varchar(100);not null;index"`
	Resource   string         `json:"resource" gorm:"type:varchar(100);not null;index"`
	ResourceID *uuid.UUID     `json:"resource_id" gorm:"type:uuid;index"`
	Details    datatypes.JSON `json:"details" gorm:"type:jsonb"`
	IPAddress  string         `json:"ip_address" gorm:"type:inet"`
	UserAgent  string         `json:"user_agent" gorm:"type:text"`
	Success    bool           `json:"success" gorm:"not null;index"`
	ErrorMsg   *string        `json:"error_msg" gorm:"type:text"`

	// Relationship
	User *User `json:"-" gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL"`

	// Audit fields
	Timestamp time.Time `json:"timestamp" gorm:"autoCreateTime;index"`
}

// BeforeCreate GORM hook
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

// TableName sets the table name for AuditLog
func (AuditLog) TableName() string {
	return "audit_logs"
}
