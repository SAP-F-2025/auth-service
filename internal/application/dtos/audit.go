package dtos

import (
	"time"

	"github.com/google/uuid"
)

type AuditLogEntry struct {
	ID         uuid.UUID              `json:"id"`
	UserID     *uuid.UUID             `json:"user_id"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	ResourceID *uuid.UUID             `json:"resource_id"`
	Details    map[string]interface{} `json:"details"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Success    bool                   `json:"success"`
	ErrorMsg   *string                `json:"error_msg"`
	Timestamp  time.Time              `json:"timestamp"`
}

type AuditLogRequest struct {
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	Action    *string    `json:"action,omitempty"`
	Resource  *string    `json:"resource,omitempty"`
	Success   *bool      `json:"success,omitempty"`
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
	Limit     int        `json:"limit" validate:"min=1,max=100"`
	Offset    int        `json:"offset" validate:"min=0"`
}

type SearchAuditLogRequest struct {
	Query     string                 `json:"query"`
	Filters   map[string]interface{} `json:"filters"`
	StartDate *time.Time             `json:"start_date,omitempty"`
	EndDate   *time.Time             `json:"end_date,omitempty"`
	Limit     int                    `json:"limit" validate:"min=1,max=100"`
	Offset    int                    `json:"offset" validate:"min=0"`
}

type AuditLogResponse struct {
	Data       []*AuditLogEntry `json:"data"`
	TotalCount int              `json:"total_count"`
	Limit      int              `json:"limit"`
	Offset     int              `json:"offset"`
}

type SecurityAlert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	UserID      *uuid.UUID             `json:"user_id"`
	IPAddress   string                 `json:"ip_address"`
	Details     map[string]interface{} `json:"details"`
	Resolved    bool                   `json:"resolved"`
	CreatedAt   time.Time              `json:"created_at"`
	ResolvedAt  *time.Time             `json:"resolved_at"`
}

// Common response structures
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorInfo  `json:"error,omitempty"`
}

type ErrorInfo struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	TotalCount int         `json:"total_count"`
	Limit      int         `json:"limit"`
	Offset     int         `json:"offset"`
	HasNext    bool        `json:"has_next"`
}

// Validation error structure
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}
