package openvpn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
)

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

func TestSendCommandHonorsContextWhileWaitingForCommandLock(t *testing.T) {
	t.Parallel()

	client := newCommandTestClient()
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstErrCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(firstCtx, "first", false)
		firstErrCh <- err
	}()

	requireCommand(t, client, "first")

	secondCtx, cancelSecond := context.WithCancel(t.Context())
	secondErrCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(secondCtx, "second", false)
		secondErrCh <- err
	}()

	cancelSecond()
	requireErrorIs(t, secondErrCh, context.Canceled)

	cancelFirst()
	requireErrorIs(t, firstErrCh, context.Canceled)
	client.Shutdown(t.Context())
}

func TestSendCommandHonorsContextWhileEnqueueing(t *testing.T) {
	t.Parallel()

	client := newCommandTestClient()
	for range cap(client.commandsCh) {
		client.commandsCh <- "queued"
	}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(ctx, "blocked", false)
		errCh <- err
	}()

	requireCommandLockHeld(t, client)
	cancel()
	requireErrorIs(t, errCh, context.Canceled)
	client.Shutdown(t.Context())
}

func TestSendCommandHonorsContextWhileWaitingForResponse(t *testing.T) {
	t.Parallel()

	client := newCommandTestClient()
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(ctx, "waiting", false)
		errCh <- err
	}()

	requireCommand(t, client, "waiting")
	cancel()
	requireErrorIs(t, errCh, context.Canceled)
	client.Shutdown(t.Context())
}

func TestSendCommandDrainsCanceledCommandResponse(t *testing.T) {
	t.Parallel()

	client := newCommandTestClient()
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstErrCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(firstCtx, "first", false)
		firstErrCh <- err
	}()

	requireCommand(t, client, "first")
	cancelFirst()
	requireErrorIs(t, firstErrCh, context.Canceled)

	secondResultCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(t.Context(), "second", false)
		secondResultCh <- err
	}()

	select {
	case command := <-client.commandsCh:
		t.Fatalf("received command %q before draining the canceled command response", command)
	case <-time.After(50 * time.Millisecond):
	}

	client.commandResponseCh <- "SUCCESS: first command succeeded"

	requireCommand(t, client, "second")

	client.commandResponseCh <- "SUCCESS: second command succeeded"

	requireErrorIs(t, secondResultCh, nil)
	client.Shutdown(t.Context())
}

func TestShutdownUnblocksSendCommand(t *testing.T) {
	t.Parallel()

	client := newCommandTestClient()
	errCh := make(chan error, 1)

	go func() {
		_, err := client.SendCommand(context.Background(), "waiting", false)
		errCh <- err
	}()

	requireCommand(t, client, "waiting")
	client.Shutdown(t.Context())
	requireErrorIs(t, errCh, ErrConnectionTerminated)
}

func newCommandTestClient() *Client {
	conf := config.Defaults
	conf.OpenVPN.CommandTimeout = time.Hour

	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), &conf) //nolint:sloglint
}

func requireCommand(t *testing.T, client *Client, expected string) {
	t.Helper()

	select {
	case actual := <-client.commandsCh:
		if actual != expected {
			t.Fatalf("received command %q, want %q", actual, expected)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for command %q", expected)
	}
}

func requireCommandLockHeld(t *testing.T, client *Client) {
	t.Helper()

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline.C:
			t.Fatal("timeout waiting for command lock")
		case <-ticker.C:
			if len(client.commandLock) == 0 {
				return
			}
		}
	}
}

func requireErrorIs(t *testing.T, errCh <-chan error, target error) {
	t.Helper()

	select {
	case err := <-errCh:
		if target == nil && err != nil {
			t.Fatalf("received unexpected error %v", err)
		}

		if target != nil && !errors.Is(err, target) {
			t.Fatalf("received error %v, want %v", err, target)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for error %v", target)
	}
}
