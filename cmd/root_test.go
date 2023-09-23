package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecuteVersion(t *testing.T) {
	os.Args = []string{"openvpn-auth-oauth2", "--version"}

	returnCode := Execute("version", "commit", "date")
	assert.Equal(t, returnCode, 0)
	// Output:
	//version: version
	//commit: commit
	//date: date
	//go: go1.21.1
}
