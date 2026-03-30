//go:build unix

package cmd

import (
	"syscall"
)

const SIGUSR1 = syscall.SIGUSR1
