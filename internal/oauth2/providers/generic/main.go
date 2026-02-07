package generic

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const Name = "generic"

type Provider struct {
	celEvalPrg cel.Program
	Conf       config.Config
}

// NewProvider creates a new generic provider from the supplied configuration.
// The http.Client argument is ignored because the provider uses the global
// client from the oauth2 package.
func NewProvider(_ context.Context, conf config.Config, _ *http.Client) (*Provider, error) {
	provider := &Provider{
		Conf: conf,
	}

	celEvalPrg, err := provider.setupCEL()
	if err != nil {
		return nil, err
	}

	provider.celEvalPrg = celEvalPrg

	return provider, nil
}

// GetName returns the identifier of this provider implementation.
func (p Provider) GetName() string {
	return Name
}

func (p Provider) setupCEL() (cel.Program, error) {
	if p.Conf.OAuth2.OpenVPNUsernameCEL == "" {
		return nil, nil //nolint:nilnil // No CEL expression configured, so we don't need to set up a program.
	}

	env, err := cel.NewEnv(
		cel.VariableWithDoc("oauth2TokenClaims", cel.MapType(cel.StringType, cel.DynType), "The claims of the OAuth2 ID token"),
		ext.Strings(ext.StringsVersion(4)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	prg, issues := env.Compile(p.Conf.OAuth2.OpenVPNUsernameCEL)
	if issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	celEvalPrg, err := env.Program(prg)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return celEvalPrg, nil
}
