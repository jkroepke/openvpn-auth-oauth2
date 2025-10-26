package util_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util/testutil"
	"github.com/stretchr/testify/require"
)

// TestArgvToStrings_NilInput tests that ArgvToStrings returns nil when given a nil pointer.
func TestArgvToStrings_NilInput(t *testing.T) {
	t.Parallel()

	result := util.ArgvToStrings(nil)
	require.Nil(t, result, "Expected nil for nil input")
}

// TestArgvToStrings_EmptyArray tests that ArgvToStrings returns an empty slice for an empty argv array.
func TestArgvToStrings_EmptyArray(t *testing.T) {
	t.Parallel()

	// Create a NULL-terminated array with just NULL
	argv := testutil.CreateEmptyCStringArray()
	defer testutil.FreeCStringArray(argv, nil)

	result := util.ArgvToStrings(argv)
	require.NotNil(t, result, "Expected empty slice, not nil")
	require.Empty(t, result, "Expected empty slice")
}

// TestArgvToStrings_SingleString tests conversion of a single string.
func TestArgvToStrings_SingleString(t *testing.T) {
	t.Parallel()

	testStr := "test-string"

	argv, cStrings := testutil.CreateCStringArray([]string{testStr})
	defer testutil.FreeCStringArray(argv, cStrings)

	result := util.ArgvToStrings(argv)
	require.Len(t, result, 1, "Expected 1 element")
	require.Equal(t, testStr, result[0], "GetConnectMessage should match")
}

// TestArgvToStrings_MultipleStrings tests conversion of multiple strings.
func TestArgvToStrings_MultipleStrings(t *testing.T) {
	t.Parallel()

	testStrings := []string{
		"first-arg",
		"second-arg",
		"third-arg",
		"fourth-arg",
	}

	argv, cStrings := testutil.CreateCStringArray(testStrings)
	defer testutil.FreeCStringArray(argv, cStrings)

	result := util.ArgvToStrings(argv)
	require.Len(t, result, len(testStrings), "Should have correct number of elements")
	require.Equal(t, testStrings, result, "All strings should match")
}

// TestArgvToStrings_EmptyStrings tests conversion of empty strings.
func TestArgvToStrings_EmptyStrings(t *testing.T) {
	t.Parallel()

	testStrings := []string{"", "non-empty", "", ""}

	argv, cStrings := testutil.CreateCStringArray(testStrings)
	defer testutil.FreeCStringArray(argv, cStrings)

	result := util.ArgvToStrings(argv)
	require.Len(t, result, len(testStrings), "Should have correct number of elements")
	require.Equal(t, testStrings, result, "All strings including empty ones should match")
}

// TestArgvToStrings_SpecialCharacters tests conversion of strings with special characters.
func TestArgvToStrings_SpecialCharacters(t *testing.T) {
	t.Parallel()

	testStrings := []string{
		"path/to/file.so",
		"--option=value",
		"unix:///var/run/socket",
		"/etc/openvpn/password",
		"user@example.com",
		"key=value with spaces",
		"unicode-🔒-test",
		"line1\nline2",
		"tab\there",
	}

	argv, cStrings := testutil.CreateCStringArray(testStrings)
	defer testutil.FreeCStringArray(argv, cStrings)

	result := util.ArgvToStrings(argv)
	require.Len(t, result, len(testStrings), "Should have correct number of elements")
	require.Equal(t, testStrings, result, "All special character strings should match")
}

// TestArgvToStrings_RealWorldExample tests a realistic OpenVPN plugin argv example.
func TestArgvToStrings_RealWorldExample(t *testing.T) {
	t.Parallel()

	// Simulate a typical OpenVPN plugin invocation:
	// /path/to/openvpn-auth-oauth2.so unix:///var/run/openvpn-auth.sock /etc/openvpn/password
	testStrings := []string{
		"/usr/lib/openvpn/plugins/openvpn-auth-oauth2.so",
		"unix:///var/run/openvpn-auth.sock",
		"/etc/openvpn/password",
	}

	argv, cStrings := testutil.CreateCStringArray(testStrings)
	defer testutil.FreeCStringArray(argv, cStrings)

	result := util.ArgvToStrings(argv)
	require.Len(t, result, 3, "Should have 3 elements")
	require.Equal(t, testStrings[0], result[0], "Plugin path should match")
	require.Equal(t, testStrings[1], result[1], "Socket address should match")
	require.Equal(t, testStrings[2], result[2], "Password file should match")
}
