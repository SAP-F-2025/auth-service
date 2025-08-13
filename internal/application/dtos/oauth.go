package dtos

import (
	"time"

	"github.com/google/uuid"
)

type CreateClientRequest struct {
	Name         string   `json:"name" validate:"required,min=3,max=100"`
	Description  string   `json:"description" validate:"max=255"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1"`
	Scopes       []string `json:"scopes" validate:"required,min=1"`
	IsPublic     bool     `json:"is_public"`
}

type UpdateClientRequest struct {
	Name         *string  `json:"name,omitempty" validate:"omitempty,min=3,max=100"`
	Description  *string  `json:"description,omitempty" validate:"omitempty,max=255"`
	RedirectURIs []string `json:"redirect_uris,omitempty" validate:"omitempty,min=1"`
	Scopes       []string `json:"scopes,omitempty" validate:"omitempty,min=1"`
	IsActive     *bool    `json:"is_active,omitempty"`
}

type ClientResponse struct {
	ID           uuid.UUID `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scopes       []string  `json:"scopes"`
	IsPublic     bool      `json:"is_public"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
