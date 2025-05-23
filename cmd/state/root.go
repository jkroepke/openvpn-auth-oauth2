package state

import (
	"fmt"
	"io"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func Execute(args []string, logWriter io.Writer) int {
	if len(args) != 5 {
		_, _ = fmt.Fprintf(logWriter, "Unknown sub-command. Usage: %s state decrypt <secret> <state>\n", args[0])

		return 1
	}

	session, err := state.NewWithEncodedToken(args[4], args[3])
	if err != nil {
		_, _ = fmt.Fprintln(logWriter, err)

		return 1
	}

	_, _ = fmt.Fprintf(logWriter, "%#v\n", session)

	return 0
}
