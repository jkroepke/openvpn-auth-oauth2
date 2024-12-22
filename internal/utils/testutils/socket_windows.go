//go:build windows

package testutils

func GetGIDOfFile(_ string) (int, error) {
	return 0, nil
}

func GetPermissionsOfFile(_ string) (string, error) {
	return "", nil
}
