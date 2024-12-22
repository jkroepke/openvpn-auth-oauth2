//go:build !windows

package testutils

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func GetGIDOfFile(fileName string) (int, error) {
	stat, err := os.Stat(fileName)
	if err != nil {
		return 0, fmt.Errorf("failed to get file stat: %w", err)
	}

	gid, ok := stat.Sys().(*syscall.Stat_t)

	if !ok {
		return 0, errors.New("no stat_t")
	}

	return int(gid.Gid), nil
}

func GetPermissionsOfFile(fileName string) (string, error) {
	stat, err := os.Stat(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to get file stat: %w", err)
	}

	return stat.Mode().Perm().String(), nil
}
