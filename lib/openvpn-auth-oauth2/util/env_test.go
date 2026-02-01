//go:build linux && cgo

package util_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEnvList_NilInput tests that NewEnvList returns an error when given a nil pointer.
func TestNewEnvList_NilInput(t *testing.T) {
	t.Parallel()

	result, err := util.NewEnvList(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, util.ErrInvalidPointer)
	require.Nil(t, result, "Expected nil result for nil input")
}

// TestNewEnvList_EmptyArray tests that NewEnvList returns an empty map for an empty envp array.
func TestNewEnvList_EmptyArray(t *testing.T) {
	t.Parallel()

	// Create a NULL-terminated array with just NULL
	envp := testutil.CreateEmptyCStringArray()
	defer testutil.FreeCStringArray(envp, nil)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.NotNil(t, result, "Expected empty map, not nil")
	require.Empty(t, result, "Expected empty map")
}

// TestNewEnvList_SingleVar tests conversion of a single environment variable.
func TestNewEnvList_SingleVar(t *testing.T) {
	t.Parallel()

	testEnv := []string{"KEY=value"}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, 1, "Expected 1 element")
	require.Equal(t, "value", result["KEY"], "Value should match")
}

// TestNewEnvList_MultipleVars tests conversion of multiple environment variables.
func TestNewEnvList_MultipleVars(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"USER=testuser",
		"SHELL=/bin/bash",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, len(testEnv), "Should have correct number of elements")

	expected := util.List{
		"PATH":  "/usr/bin:/bin",
		"HOME":  "/home/user",
		"USER":  "testuser",
		"SHELL": "/bin/bash",
	}
	require.Equal(t, expected, result, "All variables should match")
}

// TestNewEnvList_EmptyValue tests environment variables with empty values.
func TestNewEnvList_EmptyValue(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"EMPTY_VAR=",
		"NON_EMPTY=value",
		"ANOTHER_EMPTY=",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, len(testEnv), "Should have correct number of elements")

	assert.Empty(t, result["EMPTY_VAR"], "Empty value should be preserved")
	assert.Equal(t, "value", result["NON_EMPTY"], "Non-empty value should match")
	assert.Empty(t, result["ANOTHER_EMPTY"], "Empty value should be preserved")
}

// TestNewEnvList_SpecialCharacters tests environment variables with special characters.
func TestNewEnvList_SpecialCharacters(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"URL=https://example.com:8080/path?query=1",
		"ENCODED=value%20with%20percent",
		"UNICODE=🔒",
		"NEWLINE=line1\nline2",
		"TAB=col1\tcol2",
		"QUOTE=value with \"quotes\"",
		"SPACE=value with spaces",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, len(testEnv), "Should have correct number of elements")

	assert.Equal(t, "https://example.com:8080/path?query=1", result["URL"])
	assert.Equal(t, "value%20with%20percent", result["ENCODED"])
	assert.Equal(t, "🔒", result["UNICODE"])
	assert.Equal(t, "line1\nline2", result["NEWLINE"])
	assert.Equal(t, "col1\tcol2", result["TAB"])
	assert.Equal(t, "value with \"quotes\"", result["QUOTE"])
	assert.Equal(t, "value with spaces", result["SPACE"])
}

// TestNewEnvList_EqualsInValue tests environment variables with '=' in the value.
func TestNewEnvList_EqualsInValue(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"EQUATION=x=y+z",
		"MULTIPLE=a=b=c=d",
		"BASE64=dGVzdA==",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, len(testEnv), "Should have correct number of elements")

	assert.Equal(t, "x=y+z", result["EQUATION"], "Value with '=' should be preserved")
	assert.Equal(t, "a=b=c=d", result["MULTIPLE"], "Multiple '=' should be preserved")
	assert.Equal(t, "dGVzdA==", result["BASE64"], "Base64 value should be preserved")
}

// TestNewEnvList_WhitespaceInKey tests environment variables with whitespace in the key.
func TestNewEnvList_WhitespaceInKey(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		" KEY=value1",  // Leading space
		"KEY =value2",  // Trailing space
		" KEY =value3", // Both
		"\tKEY=value4", // Tab
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	// All keys are trimmed to "KEY", so only 1 entry (last one wins)
	require.Len(t, result, 1, "All trimmed keys should map to same entry")

	// Keys are trimmed, last value wins
	assert.Equal(t, "value4", result["KEY"], "Last value should win for duplicate trimmed keys")
	assert.NotContains(t, result, " KEY", "Keys with leading space should be trimmed")
	assert.NotContains(t, result, "KEY ", "Keys with trailing space should be trimmed")
	assert.NotContains(t, result, "\tKEY", "Keys with tab should be trimmed")
}

// TestNewEnvList_MalformedNoEquals tests that malformed variables without '=' return an error.
func TestNewEnvList_MalformedNoEquals(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"VALIDKEY=value",
		"MALFORMED",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.Error(t, err)
	require.ErrorIs(t, err, util.ErrMalformedEnvVar)
	require.Nil(t, result, "Expected nil result for malformed input")
	require.Contains(t, err.Error(), "MALFORMED", "Error should mention the malformed variable")
	require.Contains(t, err.Error(), "missing '='", "Error should mention missing '='")
}

// TestNewEnvList_MalformedEmptyKey tests that variables with empty keys return an error.
func TestNewEnvList_MalformedEmptyKey(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"VALIDKEY=value",
		"=value",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.Error(t, err)
	require.ErrorIs(t, err, util.ErrMalformedEnvVar)
	require.Nil(t, result, "Expected nil result for malformed input")
	require.Contains(t, err.Error(), "empty key", "Error should mention empty key")
}

// TestNewEnvList_MalformedWhitespaceOnlyKey tests that variables with whitespace-only keys return an error.
func TestNewEnvList_MalformedWhitespaceOnlyKey(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"VALIDKEY=value",
		"   =value",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.Error(t, err)
	require.ErrorIs(t, err, util.ErrMalformedEnvVar)
	require.Nil(t, result, "Expected nil result for malformed input")
	require.Contains(t, err.Error(), "empty key", "Error should mention empty key")
}

// TestNewEnvList_EmptyString tests that empty strings are skipped.
func TestNewEnvList_EmptyString(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"",
		"KEY=value",
		"",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	// Empty strings are skipped but still counted in the initial allocation
	require.Len(t, result, 1, "Only valid entries should be in the map")
	assert.Equal(t, "value", result["KEY"])
}

// TestNewEnvList_OpenVPNVariables tests realistic OpenVPN environment variables.
func TestNewEnvList_OpenVPNVariables(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"common_name=user@example.com",
		"username=testuser",
		"password=testpass",
		"untrusted_ip=192.168.1.100",
		"untrusted_port=12345",
		"trusted_ip=10.8.0.1",
		"trusted_port=1194",
		"ifconfig_pool_remote_ip=10.8.0.2",
		"time_unix=1698331200",
		"tls_serial_0=4A:5B:6C:7D:8E:9F",
		"X509_0_CN=user@example.com",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, len(testEnv), "Should have correct number of elements")

	assert.Equal(t, "user@example.com", result["common_name"])
	assert.Equal(t, "testuser", result["username"])
	assert.Equal(t, "testpass", result["password"])
	assert.Equal(t, "192.168.1.100", result["untrusted_ip"])
	assert.Equal(t, "10.8.0.2", result["ifconfig_pool_remote_ip"])
	assert.Equal(t, "4A:5B:6C:7D:8E:9F", result["tls_serial_0"])
}

// TestNewEnvList_DuplicateKeys tests that duplicate keys overwrite previous values.
func TestNewEnvList_DuplicateKeys(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"KEY=first",
		"KEY=second",
		"KEY=third",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	// Map will only have one entry for KEY
	require.Len(t, result, 1, "Duplicate keys should result in single entry")
	assert.Equal(t, "third", result["KEY"], "Last value should win for duplicate keys")
}

// TestNewEnvList_LongValues tests environment variables with long values.
func TestNewEnvList_LongValues(t *testing.T) {
	t.Parallel()

	longValue := string(make([]byte, 4096))
	for i := range []byte(longValue) {
		longValue = longValue[:i] + "x"
	}

	testEnv := []string{
		"LONG_VALUE=" + longValue,
		"NORMAL=value",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, 2, "Should handle long values")
	assert.Len(t, result["LONG_VALUE"], 4096, "Long value should be preserved")
	assert.Equal(t, "value", result["NORMAL"])
}

// TestNewEnvList_CaseSensitiveKeys tests that keys are case-sensitive.
func TestNewEnvList_CaseSensitiveKeys(t *testing.T) {
	t.Parallel()

	testEnv := []string{
		"key=lowercase",
		"KEY=uppercase",
		"Key=mixedcase",
	}

	envp, cStrings := testutil.CreateCStringArray(testEnv)
	defer testutil.FreeCStringArray(envp, cStrings)

	result, err := util.NewEnvList(envp)
	require.NoError(t, err)
	require.Len(t, result, 3, "Keys should be case-sensitive")
	assert.Equal(t, "lowercase", result["key"])
	assert.Equal(t, "uppercase", result["KEY"])
	assert.Equal(t, "mixedcase", result["Key"])
}
