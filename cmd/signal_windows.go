//go:build windows

package cmd

import (
	"syscall"
)

const SIGUSR1 = syscall.Signal(-1)
