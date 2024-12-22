//go:build !windows

package testutils

import (
	"fmt"
	"os"
	"syscall"
)

func GetGIDOfFile(fileName string) (int, error) {
	stat, err := os.Stat(fileName)
	if err != nil {
		return 0, err
	}

	gid, ok := stat.Sys().(*syscall.Stat_t)

	if !ok {
		return 0, fmt.Errorf("no stat_t")
	}

	return int(gid.Gid), nil
}

func GetPermissionsOfFile(fileName string) (string, error) {
	stat, err := os.Stat(fileName)
	if err != nil {
		return "", err
	}

	return stat.Mode().Perm().String(), nil
}
