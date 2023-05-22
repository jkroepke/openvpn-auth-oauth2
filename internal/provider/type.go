package provider

import "context"

type Provider interface {
	StartDeviceAuthorization(ctx context.Context) (*DeviceCodeResponse, error)
	ValidateDeviceAuthorization(ctx context.Context) error
}

type DeviceCodeResponse struct {
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
}
