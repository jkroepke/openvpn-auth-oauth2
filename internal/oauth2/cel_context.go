package oauth2

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

const (
	celAuthContextTypeName    = "openvpn_auth_oauth2.AuthContext"
	celOpenVPNContextTypeName = "openvpn_auth_oauth2.OpenVPNContext"
	celTokenContextTypeName   = "openvpn_auth_oauth2.TokenContext"
	celUserContextTypeName    = "openvpn_auth_oauth2.UserContext"
)

type celContextSchema struct {
	construct  func(map[string]ref.Val) (any, error)
	fields     map[string]*celtypes.FieldType
	objectType *celtypes.Type
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

func newCELContextSchemas() map[string]*celContextSchema {
	return map[string]*celContextSchema{
		celAuthContextTypeName: newCELContextSchema(
			celAuthContextTypeName,
			newCELAuthContext,
			newCELStringContextField("mode", func(context *celAuthContext) *string {
				return &context.mode
			}),
		),
		celOpenVPNContextTypeName: newCELContextSchema(
			celOpenVPNContextTypeName,
			newCELOpenVPNContext,
			newCELStringContextField("commonName", func(context *celOpenVPNContext) *string {
				return &context.commonName
			}),
			newCELStringContextField("ip", func(context *celOpenVPNContext) *string {
				return &context.ip
			}),
			newCELStringContextField("sessionState", func(context *celOpenVPNContext) *string {
				return &context.sessionState
			}),
		),
		celTokenContextTypeName: newCELContextSchema(
			celTokenContextTypeName,
			newCELTokenContext,
			newCELContextField("claims", cel.MapType(cel.StringType, cel.DynType), func(context celTokenContext) map[string]any {
				return context.claims
			}),
			newCELStringContextField("ip", func(context *celTokenContext) *string {
				return &context.ip
			}),
		),
		celUserContextTypeName: newCELContextSchema(
			celUserContextTypeName,
			newCELUserContext,
			newCELStringContextField("email", func(context *celUserContext) *string {
				return &context.email
			}),
			newCELContextField("groups", cel.ListType(cel.StringType), func(context celUserContext) []string {
				return context.groups
			}),
			newCELContextField("roles", cel.ListType(cel.StringType), func(context celUserContext) []string {
				return context.roles
			}),
			newCELStringContextField("subject", func(context *celUserContext) *string {
				return &context.subject
			}),
			newCELStringContextField("username", func(context *celUserContext) *string {
				return &context.username
			}),
		),
	}
}

// celContextTypes registers the fixed fields exposed by the CEL activation.
// Explicit field getters avoid reflection and report every stable field as present,
// matching the previous map-key presence semantics for has().
func celContextTypes() cel.EnvOption {
	return func(env *cel.Env) (*cel.Env, error) {
		schemas := newCELContextSchemas()
		contextAdapter := &celContextTypeAdapter{
			Adapter: env.CELTypeAdapter(),
			schemas: schemas,
		}
		contextProvider := &celContextTypeProvider{
			Provider: env.CELTypeProvider(),
			adapter:  contextAdapter,
			schemas:  schemas,
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

	schemas map[string]*celContextSchema
}

func (a *celContextTypeAdapter) NativeToValue(value any) ref.Val {
	switch value.(type) {
	case celAuthContext, *celAuthContext:
		return a.newContextValue(celAuthContextTypeName, value)
	case celOpenVPNContext, *celOpenVPNContext:
		return a.newContextValue(celOpenVPNContextTypeName, value)
	case celTokenContext, *celTokenContext:
		return a.newContextValue(celTokenContextTypeName, value)
	case celUserContext, *celUserContext:
		return a.newContextValue(celUserContextTypeName, value)
	default:
		return a.Adapter.NativeToValue(value)
	}
}

func (a *celContextTypeAdapter) newContextValue(typeName string, value any) ref.Val {
	schema, ok := a.schemas[typeName]
	if !ok {
		return celtypes.NewErr("unknown cel context type: %s", typeName)
	}

	return &celContextValue{
		adapter: a,
		schema:  schema,
		value:   value,
	}
}

type celContextValue struct {
	adapter celtypes.Adapter
	schema  *celContextSchema
	value   any
}

var (
	_ ref.Val            = (*celContextValue)(nil)
	_ traits.FieldTester = (*celContextValue)(nil)
	_ traits.Indexer     = (*celContextValue)(nil)
)

func (v *celContextValue) ConvertToNative(typeDesc reflect.Type) (any, error) {
	valueType := reflect.TypeOf(v.value)
	if valueType.AssignableTo(typeDesc) {
		return v.value, nil
	}

	valueReflection := reflect.ValueOf(v.value)
	if valueType.Kind() == reflect.Pointer && !valueReflection.IsNil() && valueType.Elem().AssignableTo(typeDesc) {
		return valueReflection.Elem().Interface(), nil
	}

	if typeDesc.Kind() == reflect.Pointer && valueType.AssignableTo(typeDesc.Elem()) {
		valuePtr := reflect.New(typeDesc.Elem())
		valuePtr.Elem().Set(reflect.ValueOf(v.value))

		return valuePtr.Interface(), nil
	}

	return nil, fmt.Errorf("type conversion error from %q to %q", v.Type(), typeDesc)
}

func (v *celContextValue) ConvertToType(typeValue ref.Type) ref.Val {
	if typeValue == celtypes.TypeType {
		return v.schema.objectType
	}

	if typeValue.TypeName() == v.schema.objectType.TypeName() {
		return v
	}

	return celtypes.NewErr("type conversion error from %q to %q", v.Type(), typeValue)
}

func (v *celContextValue) Equal(other ref.Val) ref.Val {
	otherContext, ok := other.(*celContextValue)
	if !ok || v.schema.objectType.TypeName() != otherContext.schema.objectType.TypeName() {
		return celtypes.False
	}

	return celtypes.Bool(reflect.DeepEqual(dereferenceCELContext(v.value), dereferenceCELContext(otherContext.value)))
}

func (v *celContextValue) Get(field ref.Val) ref.Val {
	fieldType, errValue := v.findField(field)
	if errValue != nil {
		return errValue
	}

	value, err := fieldType.GetFrom(v.value)
	if err != nil {
		return celtypes.NewErrFromString(err.Error())
	}

	return v.adapter.NativeToValue(value)
}

func (v *celContextValue) IsSet(field ref.Val) ref.Val {
	fieldType, errValue := v.findField(field)
	if errValue != nil {
		return errValue
	}

	return celtypes.Bool(fieldType.IsSet(v.value))
}

func (v *celContextValue) Type() ref.Type {
	return v.schema.objectType
}

func (v *celContextValue) Value() any {
	return dereferenceCELContext(v.value)
}

func (v *celContextValue) findField(field ref.Val) (*celtypes.FieldType, ref.Val) {
	fieldName, ok := field.(celtypes.String)
	if !ok {
		return nil, celtypes.MaybeNoSuchOverloadErr(field)
	}

	fieldType, ok := v.schema.fields[string(fieldName)]
	if !ok {
		return nil, celtypes.NewErr("no such field: %s", fieldName)
	}

	return fieldType, nil
}

type celContextTypeProvider struct {
	celtypes.Provider

	adapter *celContextTypeAdapter
	schemas map[string]*celContextSchema
}

func (p *celContextTypeProvider) FindIdent(identName string) (ref.Val, bool) {
	schema, ok := p.schemas[identName]
	if ok {
		return schema.objectType, true
	}

	return p.Provider.FindIdent(identName)
}

func (p *celContextTypeProvider) FindStructType(structType string) (*celtypes.Type, bool) {
	if schema, ok := p.schemas[structType]; ok {
		return celtypes.NewTypeTypeWithParam(schema.objectType), true
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
	schema, ok := p.schemas[structType]
	if !ok {
		return p.Provider.NewValue(structType, fields)
	}

	value, err := schema.construct(fields)
	if err != nil {
		return celtypes.NewErr("construct %s: %v", structType, err)
	}

	return p.adapter.NativeToValue(value)
}

func newCELContextSchema(
	typeName string,
	construct func(map[string]ref.Val) (any, error),
	fields ...celContextField,
) *celContextSchema {
	schema := &celContextSchema{
		construct:  construct,
		fields:     make(map[string]*celtypes.FieldType, len(fields)),
		fieldNames: make([]string, 0, len(fields)),
		objectType: celtypes.NewObjectType(typeName),
	}

	for _, field := range fields {
		schema.fields[field.name] = field.fieldType
		schema.fieldNames = append(schema.fieldNames, field.name)
	}

	return schema
}

func newCELAuthContext(fields map[string]ref.Val) (any, error) {
	context := celAuthContext{}

	if err := setCELContextField(fields, "mode", &context.mode); err != nil {
		return nil, err
	}

	return context, nil
}

func newCELOpenVPNContext(fields map[string]ref.Val) (any, error) {
	context := celOpenVPNContext{}

	if err := setCELContextField(fields, "commonName", &context.commonName); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "ip", &context.ip); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "sessionState", &context.sessionState); err != nil {
		return nil, err
	}

	return context, nil
}

func newCELTokenContext(fields map[string]ref.Val) (any, error) {
	context := celTokenContext{}

	if err := setCELContextField(fields, "claims", &context.claims); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "ip", &context.ip); err != nil {
		return nil, err
	}

	return context, nil
}

func newCELUserContext(fields map[string]ref.Val) (any, error) {
	context := celUserContext{
		groups: make([]string, 0),
		roles:  make([]string, 0),
	}

	if err := setCELContextField(fields, "email", &context.email); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "groups", &context.groups); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "roles", &context.roles); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "subject", &context.subject); err != nil {
		return nil, err
	}

	if err := setCELContextField(fields, "username", &context.username); err != nil {
		return nil, err
	}

	return context, nil
}

func setCELContextField[Value any](fields map[string]ref.Val, fieldName string, target *Value) error {
	value, ok := fields[fieldName]
	if !ok {
		return nil
	}

	nativeValue, err := value.ConvertToNative(reflect.TypeFor[Value]())
	if err != nil {
		return fmt.Errorf("convert field %q: %w", fieldName, err)
	}

	typedValue, ok := nativeValue.(Value)
	if !ok {
		return fmt.Errorf("convert field %q: expected %T, got %T", fieldName, *target, nativeValue)
	}

	*target = typedValue

	return nil
}

func newCELContextField[Context, Value any](fieldName string, fieldType *cel.Type, getValue func(Context) Value) celContextField {
	return celContextField{
		name: fieldName,
		fieldType: &celtypes.FieldType{
			Type: fieldType,
			IsSet: func(target any) bool {
				_, ok := asCELContext[Context](target)

				return ok
			},
			GetFrom: func(target any) (any, error) {
				context, ok := asCELContext[Context](target)
				if !ok {
					return nil, fmt.Errorf("invalid cel context for field %q: %T", fieldName, target)
				}

				return getValue(context), nil
			},
		},
	}
}

// newCELStringContextField returns pointers to activation-owned strings so the
// CEL adapter can convert them without first allocating an interface-boxed copy.
func newCELStringContextField[Context any](fieldName string, getValue func(*Context) *string) celContextField {
	return celContextField{
		name: fieldName,
		fieldType: &celtypes.FieldType{
			Type: cel.StringType,
			IsSet: func(target any) bool {
				_, ok := asCELContext[Context](target)

				return ok
			},
			GetFrom: func(target any) (any, error) {
				context, ok := target.(*Context)
				if ok && context != nil {
					return getValue(context), nil
				}

				return getCELStringContextFieldFromValue(fieldName, target, getValue)
			},
		},
	}
}

func getCELStringContextFieldFromValue[Context any](
	fieldName string,
	target any,
	getValue func(*Context) *string,
) (any, error) {
	context, ok := target.(Context)
	if !ok {
		return nil, fmt.Errorf("invalid cel context for field %q: %T", fieldName, target)
	}

	return getValue(&context), nil
}

func asCELContext[Context any](target any) (Context, bool) {
	context, ok := target.(Context)
	if ok {
		return context, true
	}

	contextPtr, ok := target.(*Context)
	if ok && contextPtr != nil {
		return *contextPtr, true
	}

	var zero Context

	return zero, false
}

func dereferenceCELContext(value any) any {
	valueReflection := reflect.ValueOf(value)
	if valueReflection.Kind() == reflect.Pointer && !valueReflection.IsNil() {
		return valueReflection.Elem().Interface()
	}

	return value
}
