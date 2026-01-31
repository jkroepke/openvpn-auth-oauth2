package generic

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const Name = "generic"

type Provider struct {
	Conf   config.Config
	celPrg cel.Program
}

// NewProvider creates a new generic provider from the supplied configuration.
// The http.Client argument is ignored because the provider uses the global
// client from the oauth2 package.
func NewProvider(_ context.Context, conf config.Config, _ *http.Client) (*Provider, error) {
	env, err := cel.NewEnv(
		cel.Variable("openvpnCommonName", cel.StringType),
		cel.Variable("openvpnIPAddr", cel.StringType),
		cel.Variable("tokenClaims", cel.AnyType),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	prg, issues := env.Compile(conf.OAuth2.Validate.CEL)

	if issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	evalPrg, err := env.Program(prg)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return &Provider{
		Conf:   conf,
		celPrg: evalPrg,
	}, nil
}

// GetName returns the identifier of this provider implementation.
func (p Provider) GetName() string {
	return Name
}
