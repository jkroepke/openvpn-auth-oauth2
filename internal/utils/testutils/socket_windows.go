//go:build windows

package testutils

// GetGIDOfFile returns 0 on Windows as the concept of GID is not used.
func GetGIDOfFile(_ string) (int, error) {
	return 0, nil
}

// GetPermissionsOfFile returns an empty string on Windows as file permission
// bits are not represented in the same way as on Unix systems.
func GetPermissionsOfFile(_ string) (string, error) {
	return "", nil
}
