package main

import "C"
import (
	"unsafe"
)

func ArgvToStrings(argv **C.char) []string {
	if argv == nil {
		return nil
	}

	// Count
	count := 0
	for p := argv; *p != nil; p = (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Sizeof(*p))) {
		count++
	}

	// Build slice and convert
	ptrs := unsafe.Slice(argv, count)
	strs := make([]string, count)
	for i, s := range ptrs {
		strs[i] = C.GoString(s)
	}
	return strs
}
