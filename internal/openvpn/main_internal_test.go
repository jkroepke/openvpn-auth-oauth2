package openvpn

import "testing"

func TestManagementCommandName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		command string
		expect  string
	}{
		{name: "empty", command: "", expect: ""},
		{name: "whitespace", command: " \t\n", expect: ""},
		{name: "arguments", command: "status 3", expect: "status"},
		{name: "leading whitespace", command: " \tstatus 3", expect: "status"},
		{name: "unicode whitespace", command: "\u2003status 3", expect: "status"},
		{name: "first line", command: "status 3\r\npassword Auth secret", expect: "status"},
		{name: "empty first line", command: "\r\nstatus 3", expect: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if name := managementCommandName(tc.command); name != tc.expect {
				t.Errorf("managementCommandName(%q) = %q, want %q", tc.command, name, tc.expect)
			}
		})
	}
}
