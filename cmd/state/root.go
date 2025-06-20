package state

import (
	"fmt"
	"io"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// Execute decodes an encrypted OAuth2 state token and writes the resulting
// session data to the provided writer. It expects the arguments:
//
//     <program> state decrypt <secret> <state>
//
// The secret must match the one used by openvpn-auth-oauth2. The function
// returns 0 on success or 1 on failure.

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
