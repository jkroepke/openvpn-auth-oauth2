package main

/*
#define DUMMY_OK 0
*/
import "C"

// main function as required by Go for building a shared library.
func main() {
	// This function is here to satisfy Go's requirement of having a main function.
	// The main functionality is implemented in the openvpn_plugin_open_v3 function,
	// which will be called from C.
}
