package util

import (
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
)

// ArgvToStrings converts a C-style NULL-terminated array of strings to a Go string slice.
// This function is used to convert OpenVPN plugin arguments passed from C to Go.
//
// Parameters:
//   - argv: Pointer to a NULL-terminated array of C strings
//
// Returns:
//   - []string: A slice containing the converted strings, or nil if argv is nil
func ArgvToStrings(argv **c.Char) []string {
	if argv == nil {
		return nil
	}

	// Count
	count := 0
	for p := argv; *p != nil; p = (**c.Char)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Sizeof(*p))) {
		count++
	}

	// Build slice and convert
	ptrs := unsafe.Slice(argv, count)

	stringArgs := make([]string, count)
	
	for i, s := range ptrs {
		stringArgs[i] = c.GoString(s)
	}

	return stringArgs
}
