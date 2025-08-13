package dtos

import (
	"time"
)

// Authentication DTOs
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Remember bool   `json:"remember"`
}

type LoginResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresIn    int64         `json:"expires_in"`
	TokenType    string        `json:"token_type"`
	RequiresMFA  bool          `json:"requires_mfa"`
	ChallengeID  *string       `json:"challenge_id,omitempty"`
}

type RegisterRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required,min=1,max=100"`
	LastName  string `json:"last_name" validate:"required,min=1,max=100"`
	Role      string `json:"role" validate:"required,oneof=student teacher"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type TokenValidationResponse struct {
	Valid  bool                   `json:"valid"`
	User   *UserResponse          `json:"user,omitempty"`
	Claims map[string]interface{} `json:"claims,omitempty"`
}

type TokenIntrospectionResponse struct {
	Active    bool      `json:"active"`
	ClientID  string    `json:"client_id,omitempty"`
	Username  string    `json:"username,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	ExpiresAt time.Time `json:"exp,omitempty"`
	IssuedAt  time.Time `json:"iat,omitempty"`
	Subject   string    `json:"sub,omitempty"`
}
