package provider

import "context"

type Provider interface {
	StartAuthentication(ctx context.Context) (string, error)
	ValidateAuthentication(ctx context.Context) error
}
