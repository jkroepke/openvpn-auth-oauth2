package testutil

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
)

// CreateCStringArray creates a NULL-terminated C string array from a Go string slice.
// This is a helper function for testing CGO code.
//
// The caller is responsible for freeing the memory by calling FreeCStringArray.
//
// Parameters:
//   - strings: A slice of Go strings to convert
//
// Returns:
//   - **c.Char: Pointer to a NULL-terminated array of C strings
//   - []*c.Char: Slice of individual C string pointers (for cleanup)
func CreateCStringArray(strings []string) (**c.Char, []*c.Char) {
	// Allocate C strings
	cStrings := make([]*c.Char, len(strings))
	for i, s := range strings {
		cStrings[i] = c.CString(s)
	}

	// Allocate array of pointers (len + 1 for NULL terminator)
	ptrSize := unsafe.Sizeof(uintptr(0))
	arraySize := (uint64(len(strings)) + 1) * uint64(ptrSize)
	argv := C.malloc(C.size_t(arraySize))

	// Fill the array
	for i, cStr := range cStrings {
		ptr := (**c.Char)(unsafe.Add(argv, uintptr(i)*ptrSize))
		*ptr = cStr
	}

	// NULL terminator
	*(**c.Char)(unsafe.Add(argv, uintptr(len(strings))*ptrSize)) = nil

	return (**c.Char)(argv), cStrings
}

// FreeCStringArray frees memory allocated by CreateCStringArray.
//
// Parameters:
//   - argv: The array pointer returned by CreateCStringArray
//   - cStrings: The slice of C string pointers returned by CreateCStringArray
func FreeCStringArray(argv **c.Char, cStrings []*c.Char) {
	// Free individual strings
	for _, cStr := range cStrings {
		C.free(unsafe.Pointer(cStr))
	}
	// Free the array
	C.free(unsafe.Pointer(argv))
}

// CreateEmptyCStringArray creates a NULL-terminated empty C string array.
// This is useful for testing edge cases.
//
// The caller is responsible for freeing the memory by calling c.Free on the returned pointer.
//
// Returns:
//   - **c.Char: Pointer to a NULL-terminated empty array
func CreateEmptyCStringArray() **c.Char {
	// Allocate array with just NULL terminator
	argv := C.malloc(C.size_t(unsafe.Sizeof(uintptr(0))))
	*(**c.Char)(argv) = nil

	return (**c.Char)(argv)
}
