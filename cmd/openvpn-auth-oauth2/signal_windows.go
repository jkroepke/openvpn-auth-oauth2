//go:build windows

package main

import (
	"syscall"
)

const SIGUSR1 = syscall.Signal(-1)
