package services

import (
	"context"

	"github.com/SAP-2025/Auth-Service/internal/application/dtos"
)

type OAuthService interface {
	// OAuth2 flows
	GetAuthURL(ctx context.Context, provider, state string) (string, error)
	HandleCallback(ctx context.Context, provider, code, state string) (*dtos.LoginResponse, error)

	// Token management
	ValidateToken(ctx context.Context, token string) (*dtos.TokenValidationResponse, error)
	IntrospectToken(ctx context.Context, token string) (*dtos.TokenIntrospectionResponse, error)

	// Client management (for service-to-service auth)
	CreateClient(ctx context.Context, req *dtos.CreateClientRequest) (*dtos.ClientResponse, error)
	GetClient(ctx context.Context, clientID string) (*dtos.ClientResponse, error)
	UpdateClient(ctx context.Context, clientID string, req *dtos.UpdateClientRequest) (*dtos.ClientResponse, error)
	DeleteClient(ctx context.Context, clientID string) error
}
