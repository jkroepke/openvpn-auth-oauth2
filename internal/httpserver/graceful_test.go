package httpserver_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httpserver"
	"github.com/stretchr/testify/require"
)

func TestListenDrainsActiveRequestAfterCancellation(t *testing.T) {
	t.Parallel()

	var listenConfig net.ListenConfig

	reserved, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := reserved.Addr().String()
	require.NoError(t, reserved.Close())

	entered := make(chan struct{})
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release

		if r.Context().Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		w.WriteHeader(http.StatusOK)
	})

	server := httpserver.NewHTTPServer(
		httpserver.ServerNameDefault, slog.New(slog.DiscardHandler),
		config.HTTP{Listen: addr}, mux,
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serveDone := make(chan error, 1)

	go func() {
		serveDone <- server.Listen(ctx)
	}()

	var dialer net.Dialer

	require.Eventually(t, func() bool {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return false
		}

		_ = conn.Close()

		return true
	}, time.Second, 10*time.Millisecond)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/slow", http.NoBody)
	require.NoError(t, err)

	responseDone := make(chan error, 1)
	httpClient := &http.Client{Timeout: 2 * time.Second}

	go func() {
		resp, err := httpClient.Do(req)
		if err != nil {
			responseDone <- err

			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseDone <- fmt.Errorf("unexpected status: %d", resp.StatusCode)

			return
		}

		responseDone <- nil
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("slow request never reached the server")
	}

	cancel()

	select {
	case err := <-serveDone:
		t.Fatalf("server exited before draining the active request: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-responseDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("request did not complete during graceful drain")
	}

	select {
	case err := <-serveDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("server did not exit after draining request")
	}
}
