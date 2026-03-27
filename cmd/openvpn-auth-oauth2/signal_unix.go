//go:build unix

package main

import (
	"syscall"
)

const SIGUSR1 = syscall.SIGUSR1
