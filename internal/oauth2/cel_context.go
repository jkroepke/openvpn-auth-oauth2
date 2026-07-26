package oauth2

import (
	"fmt"
	"slices"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const (
	celAuthContextTypeName    = "openvpn_auth_oauth2.AuthContext"
	celOpenVPNContextTypeName = "openvpn_auth_oauth2.OpenVPNContext"
	celTokenContextTypeName   = "openvpn_auth_oauth2.TokenContext"
	celUserContextTypeName    = "openvpn_auth_oauth2.UserContext"
)

type celContextSchema struct {
	fields     map[string]*celtypes.FieldType
	fieldNames []string
}

type celContextField struct {
	fieldType *celtypes.FieldType
	name      string
}

type celAuthContext struct {
	mode string
}

type celOpenVPNContext struct {
	commonName   string
	ip           string
	sessionState string
}

type celTokenContext struct {
	claims map[string]any
	ip     string
}

type celUserContext struct {
	email    string
	subject  string
	username string
	groups   []string
	roles    []string
}

func newCELContextSchemas() map[string]celContextSchema {
	return map[string]celContextSchema{
		celAuthContextTypeName: newCELContextSchema(
			newCELContextField("mode", cel.StringType, func(context celAuthContext) string {
				return context.mode
			}),
		),
		celOpenVPNContextTypeName: newCELContextSchema(
			newCELContextField("commonName", cel.StringType, func(context celOpenVPNContext) string {
				return context.commonName
			}),
			newCELContextField("ip", cel.StringType, func(context celOpenVPNContext) string {
				return context.ip
			}),
			newCELContextField("sessionState", cel.StringType, func(context celOpenVPNContext) string {
				return context.sessionState
			}),
		),
		celTokenContextTypeName: newCELContextSchema(
			newCELContextField("claims", cel.MapType(cel.StringType, cel.DynType), func(context celTokenContext) map[string]any {
				return context.claims
			}),
			newCELContextField("ip", cel.StringType, func(context celTokenContext) string {
				return context.ip
			}),
		),
		celUserContextTypeName: newCELContextSchema(
			newCELContextField("email", cel.StringType, func(context celUserContext) string {
				return context.email
			}),
			newCELContextField("groups", cel.ListType(cel.StringType), func(context celUserContext) []string {
				return context.groups
			}),
			newCELContextField("roles", cel.ListType(cel.StringType), func(context celUserContext) []string {
				return context.roles
			}),
			newCELContextField("subject", cel.StringType, func(context celUserContext) string {
				return context.subject
			}),
			newCELContextField("username", cel.StringType, func(context celUserContext) string {
				return context.username
			}),
		),
	}
}

// celContextTypes registers the fixed fields exposed by the CEL activation.
// Explicit field getters avoid reflection and report every stable field as present,
// matching the previous map-key presence semantics for has().
func celContextTypes() cel.EnvOption {
	return func(env *cel.Env) (*cel.Env, error) {
		contextAdapter := &celContextTypeAdapter{Adapter: env.CELTypeAdapter()}
		contextProvider := &celContextTypeProvider{
			Provider: env.CELTypeProvider(),
			schemas:  newCELContextSchemas(),
		}

		env, err := cel.CustomTypeAdapter(contextAdapter)(env)
		if err != nil {
			return nil, fmt.Errorf("register cel context type adapter: %w", err)
		}

		env, err = cel.CustomTypeProvider(contextProvider)(env)
		if err != nil {
			return nil, fmt.Errorf("register cel context type provider: %w", err)
		}

		return env, nil
	}
}

type celContextTypeAdapter struct {
	celtypes.Adapter
}

func (a *celContextTypeAdapter) NativeToValue(value any) ref.Val {
	switch context := value.(type) {
	case celAuthContext:
		return celtypes.NewStringStringMap(a.Adapter, map[string]string{
			"mode": context.mode,
		})
	case celOpenVPNContext:
		return celtypes.NewStringStringMap(a.Adapter, map[string]string{
			"commonName":   context.commonName,
			"ip":           context.ip,
			"sessionState": context.sessionState,
		})
	case celTokenContext:
		return celtypes.NewStringInterfaceMap(a.Adapter, map[string]any{
			"claims": context.claims,
			"ip":     context.ip,
		})
	case celUserContext:
		return celtypes.NewStringInterfaceMap(a.Adapter, map[string]any{
			"email":    context.email,
			"groups":   context.groups,
			"roles":    context.roles,
			"subject":  context.subject,
			"username": context.username,
		})
	default:
		return a.Adapter.NativeToValue(value)
	}
}

type celContextTypeProvider struct {
	celtypes.Provider

	schemas map[string]celContextSchema
}

func (p *celContextTypeProvider) FindStructType(structType string) (*celtypes.Type, bool) {
	if _, ok := p.schemas[structType]; ok {
		return celtypes.NewTypeTypeWithParam(celtypes.NewObjectType(structType)), true
	}

	return p.Provider.FindStructType(structType)
}

func (p *celContextTypeProvider) FindStructFieldNames(structType string) ([]string, bool) {
	schema, ok := p.schemas[structType]
	if ok {
		return slices.Clone(schema.fieldNames), true
	}

	return p.Provider.FindStructFieldNames(structType)
}

func (p *celContextTypeProvider) FindStructFieldType(structType, fieldName string) (*celtypes.FieldType, bool) {
	schema, ok := p.schemas[structType]
	if ok {
		fieldType, found := schema.fields[fieldName]

		return fieldType, found
	}

	return p.Provider.FindStructFieldType(structType, fieldName)
}

func (p *celContextTypeProvider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	if _, ok := p.schemas[structType]; ok {
		return celtypes.NewErr("%s is a read-only context type", structType)
	}

	return p.Provider.NewValue(structType, fields)
}

func newCELContextSchema(fields ...celContextField) celContextSchema {
	schema := celContextSchema{
		fields:     make(map[string]*celtypes.FieldType, len(fields)),
		fieldNames: make([]string, 0, len(fields)),
	}

	for _, field := range fields {
		schema.fields[field.name] = field.fieldType
		schema.fieldNames = append(schema.fieldNames, field.name)
	}

	return schema
}

func newCELContextField[Context, Value any](fieldName string, fieldType *cel.Type, getValue func(Context) Value) celContextField {
	return celContextField{
		name: fieldName,
		fieldType: &celtypes.FieldType{
			Type: fieldType,
			IsSet: func(target any) bool {
				_, ok := target.(Context)

				return ok
			},
			GetFrom: func(target any) (any, error) {
				context, ok := target.(Context)
				if !ok {
					return nil, fmt.Errorf("invalid cel context for field %q: %T", fieldName, target)
				}

				return getValue(context), nil
			},
		},
	}
}
