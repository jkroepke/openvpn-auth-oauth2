package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
)

func TestListenDrainsActiveRequestAfterCancellation(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

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

	server := NewHTTPServer(ServerNameDefault, slog.New(slog.DiscardHandler), config.HTTP{Listen: addr}, mux)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Listen(ctx) }()

	// Wait for the listener before submitting the request so the test checks
	// shutdown behavior rather than initial listener startup.
	var connected bool
	for range 100 {
		conn, dialErr := net.DialTimeout("tcp", addr, 10*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			connected = true
			break
		}
		select {
		case err := <-serveDone:
			t.Fatalf("HTTP listener exited before accepting requests: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !connected {
		t.Fatal("HTTP listener never became available")
	}

	responseDone := make(chan error, 1)
	go func() {
		resp, requestErr := http.Get("http://" + addr + "/slow") //nolint:gosec // loopback test server
		if requestErr != nil {
			responseDone <- requestErr
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
		t.Fatalf("server exited before the active request drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-responseDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not complete during graceful drain")
	}
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not exit after draining request")
	}
}
